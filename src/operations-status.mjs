import { randomUUID } from 'node:crypto';
import { decide, RULE_IDS } from './decider.mjs';
import { detect } from './detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

// Read-only bounded probes. No tokens, note bodies, real identities or IPs.
export async function collectOperationsStatus(config, matrix, { fetchImpl = fetch, commit = null } = {}) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.pathname !== '/' || app.search || app.hash) throw new Error('invalid_observation_origin');
  let recovery = { verified: false, revision: null, source: 'not_run' };
  const checks = await Promise.all([
    ['public_entry', '/', 'GET', 200], ['anonymous_notes', '/api/notes', 'GET', 401],
    ['anonymous_self_list', '/api/my/notes', 'GET', 401], ['static_seed_removed', '/data.json', 'GET', 404],
    ['anonymous_notice_edit', '/api/notices/00000000-0000-4000-8000-000000000008', 'PUT', 401],
    ['anonymous_restore', '/api/restore/00000000-0000-4000-8000-000000000010', 'POST', 401],
    ['backup_preview', '/api/recovery-plan', 'GET', 200],
  ].map(async ([id, path, method, expected]) => {
    const requestId = randomUUID();
    try {
      const response = await fetchImpl(new URL(path, app), { method, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(5000),
        alephEvidence: { caseId: id, requestKey: requestId } });
      let passed = response.status === expected;
      if (id === 'backup_preview') {
        const value = await response.json();
        passed &&= value.backupVerified === true && value.scope === 'notes';
        recovery = { verified: passed, revision: passed ? value.backupRevision : null, source: 'live_http' };
      } else await response.body?.cancel();
      return { id, request: `${method} ${path}`, source: 'live_http', expected: id === 'backup_preview' ? 'HTTP 200; verified=true; scope=notes' : `HTTP ${expected}`, observed: id === 'backup_preview' ? `HTTP ${response.status}; verified=${recovery.verified}; revision=${recovery.revision}` : `HTTP ${response.status}`, status: passed ? 'passed' : 'failed', requestId, checkedAt: new Date().toISOString() };
    } catch { return { id, request: `${method} ${path}`, source: 'live_http', expected: `HTTP ${expected}`, observed: '요청 실행 못 함', status: 'not_run', requestId, checkedAt: new Date().toISOString() }; }
  }));
  for (const [id, select, expected] of [
    ['registered_read', () => fixtureRequests().normal, 'allow'],
    ['unregistered_read', () => ({ ...fixtureRequests().normal, deviceRegistered: false }), 'deny'],
    ['compound_risk', () => fixtureRequests().suspicious, 'step_up'],
  ]) {
    const request = select(), response = await decide(request);
    checks.push({ id, request: request.route, source: 'local_fixture', expected, observed: response.decision,
      status: response.decision === expected ? 'passed' : 'failed', requestId: request.requestId, checkedAt: new Date().toISOString() });
  }
  const events = Array.from({ length: 121 }, (_, index) => ({ at: new Date(1700000000000 + index * 2000).toISOString(), method: 'GET', identity: { sub: 'practice_subject' } }));
  const detection = detect(events);
  checks.push({ id: 'burst_read_proposal', request: '121 fictional GET events / 10 minutes', source: 'local_fixture', expected: 'propose_revocation', observed: detection.action,
    status: detection.action === 'propose_revocation' ? 'passed' : 'failed', requestId: randomUUID(), checkedAt: new Date().toISOString() });
  // The roster is a plan, not execution evidence; never accept its claimed status.
  const attackMatrix = matrix.cases.map(({ id, stage, name, expected }) => ({ id, stage, name, expected,
    status: 'not_run', source: 'official_engine_unconnected', requestId: null, checkedAt: null }));
  for (const [id, request, expected] of [
    ['live_approved_own_read', 'GET /api/my/notes with official approved device', 'allow; own data only'],
    ['live_cross_owner_read', 'GET /api/notes/:id with another owner', 'deny; no data'],
    ['live_revoked_identity', 'GET /api/my/notes after official revocation', 'deny; no data'],
  ]) checks.push({ id, request, source: 'official_engine_unconnected', expected, observed: '공식 연결과 시험 세션 미제공',
    status: 'not_run', requestId: null, checkedAt: null });
  return { schema: 'vault.operations.v1', commit: /^[a-f\d]{40}$/u.test(commit ?? '') ? commit : null, requestId: randomUUID(), checkedAt: new Date().toISOString(),
    source: 'student_server_observation', policyRules: [...RULE_IDS], checks,
    counts: { passed: checks.filter(row => row.status === 'passed').length, failed: checks.filter(row => row.status === 'failed').length,
      notRun: checks.filter(row => row.status === 'not_run').length, officialEngineNotRun: attackMatrix.length },
    detection: { action: detection.action, reasonCode: detection.reasonCode, source: 'local_fixture' },
    revocation: { status: 'not_connected', liveCount: null }, recovery, attackMatrix,
    provenance: { student: ['policy', 'detection', 'UI', 'notes API', 'backup verification and restore'],
      engine: 'ALEPH SDP engine', operationalConnection: 'not provided, not verified' } };
}
