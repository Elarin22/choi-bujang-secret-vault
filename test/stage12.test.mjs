import assert from 'node:assert/strict';
import { test } from 'node:test';
import { collectOperationsStatus } from '../src/operations-status.mjs';
import { readFile } from 'node:fs/promises';
import { runAttackChecks, observeAll, observeScreens, CASES } from '../src/attack-check.mjs';
import { runRuleCheck } from '../src/rule-check.mjs';
import { verifyPolicyBackup } from '../src/policy-recovery.mjs';
const config = { publicAppUrl: 'https://fixture.local' };
const matrix = { cases: Array.from({ length: 41 }, (_, i) => ({ id: `case_${i}`, stage: 12, name: 'Practice matrix entry', expected: 'reject', status: 'passed' })) };

test('dashboard counters come from actual calls; fake matrix status never becomes execution evidence', async () => {
  const urls = [];
  const fetchImpl = async (url, options) => { urls.push(url.pathname); assert.ok(options.alephEvidence.caseId);
    assert.match(options.alephEvidence.requestKey, /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/u);
    assert.deepEqual(Object.keys(options.alephEvidence).sort(), ['caseId', 'requestKey']);
    if (url.pathname === '/api/recovery-plan') return Response.json({ backupVerified: true, scope: 'notes', backupRevision: 1 });
    return new Response(null, { status: url.pathname === '/' ? 200 : url.pathname === '/data.json' ? 404 : 401 }); };
  const out = await collectOperationsStatus(config, matrix, { fetchImpl });
  assert.equal(urls.length, 7); assert.equal(out.counts.passed, 11); assert.equal(out.counts.failed, 0);
  assert.equal(out.counts.officialEngineNotRun, 41); assert.ok(out.attackMatrix.every(row => row.status === 'not_run' && row.requestId === null));
  assert.equal(out.revocation.liveCount, null); assert.equal(out.detection.source, 'local_fixture'); assert.equal(out.recovery.verified, true);
  assert.equal(out.counts.notRun, 3);
  assert.ok(out.checks.filter(row => row.status !== 'not_run').every(row => row.requestId && row.checkedAt));
  assert.ok(out.checks.filter(row => row.source === 'official_engine_unconnected').every(row => row.requestId === null && row.checkedAt === null));
});

test('unreachable and unexpectedly open APIs remain not_run/failed; no private body is recorded', async () => {
  const fetchImpl = async url => { if (url.pathname === '/api/recovery-plan') throw new Error('private details');
    return new Response('private note text must never be retained', { status: 200 }); };
  const out = await collectOperationsStatus(config, matrix, { fetchImpl });
  assert.equal(out.counts.failed, 5); assert.equal(out.counts.notRun, 4);
  assert.equal(out.recovery.verified, false); assert.ok(!JSON.stringify(out).includes('private note text'));
  assert.ok(!JSON.stringify(out).includes('private details'));
});

test('dashboard renders server observations and clears prior successes if a new read fails', async () => {
  const elements = new Map();
  const element = () => ({ textContent: '', children: [], append(child) { this.children.push(child); }, replaceChildren(...children) { this.children = children; } });
  const document = { getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); }, createElement: element };
  let unavailable = false;
  const observations = await collectOperationsStatus(config, matrix, { fetchImpl: async url => url.pathname === '/api/recovery-plan'
    ? Response.json({ backupVerified: true, scope: 'notes', backupRevision: 1 })
    : new Response(null, { status: url.pathname === '/' ? 200 : url.pathname === '/data.json' ? 404 : 401 }) });
  const source = await readFile(new URL('../src/operations-browser.mjs', import.meta.url), 'utf8');
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  await new AsyncFunction('document', 'fetch', source)(document, async () => {
    if (unavailable) throw new Error('network down');
    return Response.json(observations);
  });
  assert.ok(elements.get('counts').textContent.includes('11건 일치'));
  assert.ok(elements.get('counts').textContent.includes('3건 미실행'));
  assert.equal(elements.get('matrix').children.length, 41);
  assert.equal(elements.get('checks').children.length, 14);
  unavailable = true; await elements.get('refresh').onclick();
  assert.equal(elements.get('checks').children.length, 0); assert.equal(elements.get('matrix').children.length, 0);
  assert.equal(elements.get('counts').textContent, '미확인');
  assert.ok(elements.get('status').textContent.includes('통과로 표시하지 않습니다'));
});

const UUID = /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/u;
const target = { step: 12, publicAppUrl: 'https://fixture.local' };
const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'x-vercel-id': 'icn1::abc12-1700000000000-0123456789ab' } });
// 배포 대역: 보호 경로는 401, 없는 경로는 404, 규칙 점검은 ready:true.
const healthy = async url => {
  if (url.pathname === '/api/checks') return jsonResponse({ ready: true });
  if (url.pathname === '/api/device/status') return jsonResponse({ connected: false, approval: 'unavailable' });
  if (url.pathname === '/api/recovery-plan') return jsonResponse({ backupVerified: true, scope: 'notes' });
  if (url.pathname === '/data.json' || url.pathname === '/notes.json' || url.pathname.startsWith('/rest/')) return jsonResponse({ error: 'NOT_FOUND' }, 404);
  if (url.pathname.startsWith('/api/')) return jsonResponse({ error: 'LOGIN_REQUIRED' }, 401);
  return new Response('<html></html>', { status: 200 });
};

test('attack check sends one read-only request per case, links evidence by case ID, and stays within 24 requests', async () => {
  const calls = [];
  const rows = await observeAll(target, { fetch: async (url, options) => {
    calls.push({ url, options });
    assert.equal(options.method, 'GET');
    assert.deepEqual(Object.keys(options.alephEvidence).sort(), ['caseId', 'requestKey']);
    assert.match(options.alephEvidence.requestKey, UUID);
    assert.ok(!JSON.stringify(options.headers).includes(options.alephEvidence.requestKey));
    assert.ok(!url.href.includes(options.alephEvidence.requestKey));
    return healthy(url, options);
  } });
  assert.equal(rows.length, CASES.length);
  assert.ok(calls.length <= 24);
  assert.equal(new Set(calls.map(call => call.options.alephEvidence.requestKey)).size, calls.length);
  for (const row of rows.filter(row => row.requests.length)) {
    assert.equal(calls.filter(call => call.options.alephEvidence.caseId === row.attackId).length, 1);
    assert.equal(row.requests[0].requestId, 'abc12-1700000000000-0123456789ab');
    assert.ok(row.requests[0].checkedAt);
  }
  assert.ok(rows.filter(row => row.result === 'not_run').every(row => row.requests.length === 0));
});

test('bundle rows have exactly five values, at most 20 rows, and only blocked, breached or not_run results', async () => {
  const rows = await runAttackChecks(target.publicAppUrl, { fetch: healthy });
  assert.ok(rows.length >= 1 && rows.length <= 20);
  for (const row of rows) {
    assert.equal(Object.keys(row).sort().join(','), 'attackId,expected,observed,result,stage');
    assert.ok(['blocked', 'breached', 'not_run'].includes(row.result));
    assert.ok(Number.isInteger(row.stage) && row.stage >= 1 && row.stage <= 12);
    assert.ok(row.observed.length <= 300 && row.expected.length <= 300);
  }
  assert.equal(new Set(rows.map(row => row.attackId)).size, rows.length);
});

test('an unreachable deployment is not_run, a server error is not_run, and an open protected API is breached', async () => {
  const down = await observeAll(target, { fetch: async () => { throw new Error('private details'); } });
  assert.ok(down.every(row => row.result === 'not_run'));
  assert.ok(!JSON.stringify(down).includes('private details'));
  const broken = await observeAll(target, { fetch: async () => new Response('x', { status: 503 }) });
  assert.ok(broken.every(row => row.result === 'not_run'));
  const open = await observeAll(target, { fetch: async url => (url.pathname === '/api/my/notes'
    ? jsonResponse({ notes: [{ title: 'visible', content: 'visible' }] }) : healthy(url)) });
  assert.equal(open.find(row => row.attackId === 's03-unauth-list').result, 'breached');
  assert.equal(open.find(row => row.attackId === 's03-fake-token').result, 'breached');
  assert.equal(open.find(row => row.attackId === 's06-unregistered').result, 'blocked');
  const unready = await observeAll(target, { fetch: async url => (url.pathname === '/api/checks' ? jsonResponse({ ready: false }) : healthy(url)) });
  assert.equal(unready.find(row => row.attackId === 's07-compound').result, 'breached');
});

test('attack check accepts a URL or a config, rejects unsafe addresses, and screen checks never count as attacks', async () => {
  assert.deepEqual(await runAttackChecks(target, { fetch: healthy }), await runAttackChecks(target.publicAppUrl, { fetch: healthy }));
  await assert.rejects(runAttackChecks('http://fixture.local', { fetch: healthy }), /https/u);
  await assert.rejects(runAttackChecks('https://fixture.local/path', { fetch: healthy }), /https/u);
  await assert.rejects(runAttackChecks('not a url', { fetch: healthy }), /배포 주소/u);
  const screens = await observeScreens(target, { fetch: async url => (url.pathname === '/operations.html'
    ? new Response('<html>안전한 화면</html>', { status: 200 }) : healthy(url)) });
  assert.ok(screens.every(row => ['as_expected', 'unexpected', 'not_run'].includes(row.result)));
  const bad = await observeScreens(target, { fetch: async url => (url.pathname === '/operations.html'
    ? new Response('<html>방어 성공</html>', { status: 200 }) : healthy(url)) });
  assert.equal(bad.find(row => row.attackId === 's12-operations-screen').result, 'unexpected');
});

test('rule checks run the student decider and detector on fixed fictional input only', async () => {
  for (const id of ['s06-unregistered', 's07-compound', 's08-unknown-route', 's08-all-notes', 's08-write-notice', 's09-burst-read', 's10-policy-verified']) {
    const result = await runRuleCheck(id);
    assert.equal(result.ready, true, id);
    assert.equal(result.engineEnforced, 'not_run');
    assert.equal(result.engine, 'ALEPH SDP engine');
  }
  assert.equal(await runRuleCheck('../../etc/passwd'), null);
  assert.equal(await runRuleCheck(undefined), null);
  assert.equal(await runRuleCheck('constructor'), null);
});

test('the pinned safe-policy hash matches the committed backup and repository address', async () => {
  const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const backup = JSON.parse(await readFile(new URL('../backups/safe-policy.json', import.meta.url), 'utf8'));
  assert.equal(verifyPolicyBackup(backup, config.repoUrl).policyRevision, 1);
});

test('npm run bundle path imports only modules the isolated runner allows', async () => {
  const allowed = new Set(['node:fs', 'node:path', 'node:url', 'node:child_process', 'node:crypto']);
  for (const file of ['scripts/bundle.mjs', 'src/attack-check.mjs', 'src/decider.mjs', 'src/detect.mjs']) {
    const code = await readFile(new URL(`../${file}`, import.meta.url), 'utf8');
    const specifiers = [...code.matchAll(/(?:from\s+|import\s*\(\s*|import\s+)['"]([^'"]+)['"]/gu)].map(match => match[1]);
    for (const specifier of specifiers) assert.ok(allowed.has(specifier) || specifier.startsWith('.'), `${file} imports ${specifier}`);
    assert.doesNotMatch(code, /node:buffer|\bBuffer\.|from 'buffer'/u, file);
  }
  const attack = await readFile(new URL('../src/attack-check.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(attack, /^\s*import\s/mu);
  assert.doesNotMatch(attack, /method:\s*['"](?:POST|PUT|PATCH|DELETE)['"]/u);
});
