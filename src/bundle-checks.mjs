import { randomUUID } from 'node:crypto';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

// A failed transport/body read is not evidence of a blocked attack.
// Race the entire observation: isolation shims may ignore AbortSignal.
async function observe(url, { fetchImpl, timeoutMs, method = 'GET', headers = {}, caseId, read = response => response.text() }) {
  const controller = new AbortController();
  let timer, status = null;
  try {
    const result = await Promise.race([
      (async () => {
        const response = await fetchImpl(url, { method, headers, redirect: 'error', signal: controller.signal,
          alephEvidence: { caseId, requestKey: randomUUID() } });
        status = response.status;
        return { ran: true, status, value: await read(response) };
      })(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('observation_deadline')), timeoutMs); }),
    ]);
    return result;
  } catch { return { ran: false, status }; }
  finally { clearTimeout(timer); controller.abort(); }
}

const notRun = result => `not_run; ${result.status === null ? 'response_unavailable' : `HTTP ${result.status}; response_unreadable`}`;
const row = (attackId, expected, result, format = value => `HTTP ${value.status}`) => ({ attackId, expected,
  observed: result.ran ? format(result) : notRun(result) });

export async function runBundleChecks(config, { fetchImpl = fetch, timeoutMs = 5000 } = {}) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.pathname !== '/' || app.search || app.hash) throw new Error('invalid_observation_origin');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) throw new Error('invalid_observation_timeout');
  const request = (path, caseId, options = {}) => observe(new URL(path, app), { fetchImpl, timeoutMs, caseId, ...options });
  const tasks = [];
  const add = (id, path, expected, options, format) => tasks.push(async () => row(id, expected, await request(path, id, options), format));
  add('anonymous_read', '/api/notes', '401; 자료 없음');
  add('anonymous_create', '/api/notes', '401; 자료 없음', { method: 'POST' });
  add('malformed_token', '/api/notes', '401; 자료 없음', { headers: { Authorization: 'Bearer invalid' } });
  add('static_seed', '/data.json', '404');
  if (config.step >= 5) {
    // The publishable key is transient and never included in an observation.
    tasks.push(async () => {
      const auth = await request('/api/auth-config', 'public_auth_config', { read: response => response.json() });
      if (!auth.ran || auth.status !== 200 || typeof auth.value?.url !== 'string' || typeof auth.value?.publishableKey !== 'string') {
        return { attackId: 'direct_anonymous_read', expected: '원본 직접 접근 거부; 자료 없음', observed: 'not_run; public_auth_config_unavailable' };
      }
      const original = new URL(config.originalApiUrl);
      if (original.origin !== new URL(auth.value.url).origin || original.username || original.password || original.search || original.hash
          || original.pathname !== '/rest/v1/user_notes') throw new Error('invalid_original_api_origin');
      const result = await observe(original, { fetchImpl, timeoutMs, caseId: 'direct_anonymous_read', headers: { apikey: auth.value.publishableKey },
        read: async response => {
          if (!response.ok) { await response.text(); return 0; }
          const data = await response.json(); return Array.isArray(data) ? data.length : -1;
        } });
      return row('direct_anonymous_read', '원본 직접 접근 거부; 자료 없음', result, value => `HTTP ${value.status}; note count: ${value.value}`);
    });
    for (const [id, path] of [['public_asset_index', '/'], ['public_asset_app', '/app.js'], ['public_asset_identity', '/aleph.json']]) {
      add(id, path, '서버 키·시드 표식 없음', { read: async response => {
        const body = await response.text();
        return /sb_secret_[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(body) || body.includes(config.sampleMarker);
      } }, value => `HTTP ${value.status}; leak marker: ${value.value}`);
    }
  }
  if (config.step >= 8) for (const method of ['GET', 'PUT']) add(`anonymous_notice_${method.toLowerCase()}`,
    '/api/notices/00000000-0000-4000-8000-000000000008', '401; 공지 본문 없음', { method });
  if (config.step >= 10) {
    for (const [id, headers] of [['anonymous_restore', {}], ['malformed_restore', { Authorization: 'Bearer invalid' }]]) {
      add(id, '/api/restore/00000000-0000-4000-8000-000000000010', '401; 복원 실행 없음', { method: 'POST', headers });
    }
    add('backup_verification', '/api/recovery-plan', 'HTTP 200; backupVerified true; scope notes; 정책 쓰기 없음',
      { read: response => response.json() }, value => `HTTP ${value.status}; backupVerified=${value.value?.backupVerified === true}; scope=${value.value?.scope ?? 'none'}`);
  }
  if (config.step >= 11) {
    add('device_adapter_availability', '/api/device-status', '운영 연결 여부를 사실대로 표시; 설치 표시로 승인하지 않음',
      { read: response => response.json() }, value => `HTTP ${value.status}; connected=${value.value?.connected === true}; approval=${value.value?.approval ?? 'unknown'}`);
    add('public_connection_asset', '/connect.js', '서버 키·시드 표식 없음', { read: async response => {
      const body = await response.text(); return /sb_secret_[A-Za-z0-9_-]{12,}/u.test(body) || body.includes(config.sampleMarker);
    } }, value => `HTTP ${value.status}; leak marker: ${value.value}`);
  }
  if (config.step >= 12) add('operations_observation', '/api/operations-status', '실제 관측·가상 시험·미실행 구분; 41종 미실행을 성공으로 세지 않음',
    { read: async response => {
      const value = await response.json();
      if (value.schema !== 'vault.operations.v1' || !value.counts || ['passed', 'failed', 'notRun', 'officialEngineNotRun'].some(key => !Number.isInteger(value.counts[key]) || value.counts[key] < 0)) throw new Error('invalid_observation_response');
      return value.counts;
    } }, value => `HTTP ${value.status}; matched=${value.value.passed}; failed=${value.value.failed}; notRun=${value.value.notRun}; officialNotRun=${value.value.officialEngineNotRun}`);

  // Each task makes only anonymous/invalid-token observations; no fixture login.
  // A failed case cannot cancel unrelated observations. At most two deadlines
  // are sequential (public auth-config then the original table request).
  const results = await Promise.all(tasks.map(task => task()));
  const local = [];
  const decisionCase = async (id, patch, expected) => {
    const out = await decide({ ...fixtureRequests().normal, ...patch });
    local.push({ attackId: id, expected: `local fixture ${expected}; 운영 연결 증거 아님`, observed: `local fixture ${out.decision}; ${out.reasonCode}` });
  };
  if (config.step >= 6) {
    await decisionCase('local_unregistered_device', { deviceRegistered: false }, 'deny');
    if (config.step < 10) {
      await decisionCase('local_registered_device', {}, 'allow');
      await decisionCase('local_forged_device_flag', { deviceRegistered: 'true' }, 'deny');
      await decisionCase('local_wrong_service', { service: 'unlisted' }, 'deny');
    }
  }
  if (config.step >= 7) for (const verified of [false, true]) {
    const out = await decide({ ...fixtureRequests().suspicious, stepUp: { verified, authAgeSeconds: verified ? 60 : null } });
    local.push({ attackId: verified ? 'local_step_up_verified' : 'local_compound_risk', expected: `local fixture ${verified ? 'allow' : 'step_up'}; 운영 재인증 증거 아님`, observed: `local fixture ${out.decision}; ${out.reasonCode}` });
  }
  if (config.step >= 8 && config.step < 11) {
    await decisionCase('local_ambiguous_list', { path: '/api/notes', route: 'GET /api/notes' }, 'deny');
    await decisionCase('local_unproven_write', { method: 'PUT', path: '/api/notices/demo', route: 'PUT /api/notices/:id' }, 'deny');
  }
  if (config.step >= 9) for (const count of config.step >= 12 ? [121] : [120, 121]) {
    const events = Array.from({ length: count }, (_, index) => ({ at: new Date(1700000000000 + index * 2000).toISOString(), method: 'GET', identity: { sub: 'local_subject_fixture' } }));
    const out = detect(events);
    local.push({ attackId: `local_detection_${count}`, expected: `${count === 120 ? 'observe' : 'propose_revocation'}; 운영 회수 증거 아님`, observed: `local fixture ${out.action}; ${out.reasonCode ?? 'no_proposal'}` });
  }
  return [...results, ...local];
}
