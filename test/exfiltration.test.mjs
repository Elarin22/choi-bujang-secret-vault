import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { readAlerts } from '../xdr/exfiltration/read-alerts.mjs';
import { respond, connectDecider, isBlockableDestination } from '../xdr/exfiltration/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('../', import.meta.url);
const fixturePath = new URL('../xdr/fixtures/exfiltration.json', import.meta.url);
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const outcomes = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
const result = { schema: 'aleph.xdr.result.v1', moduleKey: 'exfiltration', decisions: outcomes };
const ids = action => outcomes.filter(row => row.action === action).map(row => row.alertId);
const range = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => `ex-${String(from + i).padStart(2, '0')}`);
const baseline = async request => ({ schema: 'aleph.decision.v1', requestId: request.requestId,
  decision: 'allow', reasonCode: 'test_baseline', ruleIds: [] });

test('exfiltration decide is standalone and independent of event IDs, addresses, order and timestamps', async () => {
  const code = await readFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(code, /\bimport\s|\bfetch\s*\(|\bprocess\.|\brequire\(/u);
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
  for (const alert of [...fixture.alerts].reverse()) {
    const renamed = { ...alert, id: 'independent-event', timestamp: '2026-10-13T03:00:00Z',
      data: { ...alert.data, srcip: '192.0.2.200', dstip: '192.0.2.201' } };
    assert.deepEqual(isolated.decide(renamed), decide(alert));
    assert.deepEqual(Object.keys(decide(alert)).sort(), ['action', 'confidence', 'reason']);
  }
});

test('exfiltration separates clear attacks, ambiguous attempts and normal events', () => {
  assert.deepEqual(ids('block'), range(1, 8));
  assert.deepEqual(ids('alert'), range(9, 16));
  assert.deepEqual(ids('record'), range(17, 24));
  // 수준만 높고 근거가 하나도 없으면 차단하지 않는다.
  const weak = fixture.alerts.find(alert => alert.id === 'ex-15');
  assert.equal(decide({ ...weak, rule: { ...weak.rule, level: 15 } }).action, 'alert');
  // 근거가 여러 개여도 처음 보는 목적지가 아니면(알려진 백업 서버 등) 차단하지 않는다.
  const known = fixture.alerts.find(alert => alert.id === 'ex-12');
  assert.equal(decide({ ...known, rule: { ...known.rule, level: 15 } }).action, 'alert');
  assert.equal(decide(null).action, 'alert');
  assert.equal(decide({ rule: {}, data: {} }).action, 'record');
});

test('exfiltration reasons never echo addresses, accounts or file names', () => {
  for (const alert of fixture.alerts) {
    const row = decide(alert);
    assert.ok(Number.isFinite(row.confidence) && row.confidence >= 0 && row.confidence <= 1);
    assert.equal(row.action, row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(!row.reason.includes(alert.data.srcip));
    assert.ok(!row.reason.includes(alert.data.dstip));
    assert.ok(!row.reason.includes(alert.data.srcuser));
    if (alert.data.file) assert.ok(!row.reason.includes(alert.data.file));
  }
});

test('exfiltration pattern file matches the constants used by decide and every pattern has evidence', async () => {
  const patterns = JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json', import.meta.url), 'utf8'));
  const code = await readFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');
  const inspect = await import(`data:text/javascript;base64,${Buffer.from(`${code}\nexport { PATTERNS };`).toString('base64')}`);
  assert.deepEqual(inspect.PATTERNS.map(p => p.name), patterns.patterns.map(p => p.name));
  for (const pattern of patterns.patterns) {
    assert.ok(pattern.name && pattern.condition && pattern.evidence);
    assert.ok(!pattern.evidence.includes('\n'));
    assert.ok(pattern.sources.every(source => /MITRE ATT&CK T10(41|48)/u.test(source)));
  }
});

test('exfiltration reader projects one safe row per original event and leaves the original untouched', async () => {
  const before = createHash('sha256').update(await readFile(fixturePath)).digest('hex');
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  for (const row of rows) assert.deepEqual(Object.keys(row).sort(), ['account', 'description', 'level', 'sourceIp', 'timestamp']);
  assert.equal(createHash('sha256').update(await readFile(fixturePath)).digest('hex'), before);

  const dir = await mkdtemp(join(tmpdir(), 'ex-read-'));
  const sample = join(dir, 'exfiltration.json');
  const secretLike = { ...fixture, alerts: [{ ...fixture.alerts[0],
    rule: { ...fixture.alerts[0].rule, description: 'token=EXAMPLE_NOT_A_SECRET 전송 user@example.com Bearer abc.def' } }] };
  await writeFile(sample, JSON.stringify(secretLike));
  const [row] = await readAlerts(sample);
  assert.doesNotMatch(row.description, /EXAMPLE_NOT_A_SECRET|user@example\.com|abc\.def/u);
});

test('exfiltration run writes a result with counts that match decide and blocks no normal event', async () => {
  const out = await runXdr({ root: fileURLToPath(root), moduleKey: 'exfiltration' });
  assert.equal(out.schema, 'aleph.xdr.result.v1');
  assert.deepEqual(out.counts, { block: 8, alert: 8, record: 8 });
  assert.deepEqual(out.decisions.filter(row => row.action === 'block').map(row => row.alertId), range(1, 8));
  assert.equal(out.decisions.filter(row => row.alertId >= 'ex-17' && row.action === 'block').length, 0);
});

test('exfiltration respond blocks only clear destinations, keeps other rules and does not duplicate the log', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ex-respond-'));
  await mkdir(join(dir, 'xdr'), { recursive: true });
  const other = { id: 'xdr.privilege.pv-01', moduleKey: 'privilege', sourceIp: '203.0.113.11', action: 'deny',
    confidence: 0.9, evidenceAlertId: 'pv-01', issuedAt: '2026-09-27T00:15:06.000Z', expiresAt: '2026-09-27T00:30:06.000Z', reason: 'pv_x' };
  await writeFile(join(dir, 'xdr', 'deny-rules.json'), JSON.stringify({ schema: 'aleph.xdr.deny.v1', rules: [other] }));
  const rules = await respond(dir, fixture, result);
  await respond(dir, fixture, result);
  assert.deepEqual(rules.map(rule => rule.evidenceAlertId), range(1, 8));
  const saved = JSON.parse(await readFile(join(dir, 'xdr', 'deny-rules.json'), 'utf8')).rules;
  assert.deepEqual(saved.filter(rule => rule.moduleKey === 'privilege'), [other]);
  assert.equal(saved.filter(rule => rule.moduleKey === 'exfiltration').length, 8);
  for (const rule of rules) {
    assert.ok(Date.parse(rule.expiresAt) > Date.parse(rule.issuedAt));
    assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.issuedAt), 15 * 60 * 1000);
    assert.equal(rule.action, 'deny');
  }
  const lines = (await readFile(join(dir, 'xdr', 'alerts.log'), 'utf8')).split('\n').filter(Boolean);
  assert.equal(lines.length, 16); // block 8 + alert 8, record 는 쌓지 않는다
  assert.doesNotMatch(lines.join('\n'), /203\.0\.113\.|198\.51\.100\.|user0\d|\.zip|\.7z/u);
  await assert.rejects(respond(dir, fixture, { ...result, decisions: result.decisions.slice(1) }));
});

test('exfiltration connection denies attack destinations only and passes normal requests to the base decider', async () => {
  const rules = await respond(await mkdtemp(join(tmpdir(), 'ex-conn-')), fixture, result);
  const gated = connectDecider(baseline, rules);
  const counts = { attackDenied: 0, normalDenied: 0, ambiguousDenied: 0, expiredDenied: 0 };
  for (const row of outcomes) {
    const alert = fixture.alerts.find(item => item.id === row.alertId);
    const at = new Date(Date.parse(alert.timestamp) + 1000).toISOString();
    const request = { requestId: row.alertId, at };
    const verified = { destinationIp: alert.data.dstip, destinationVerified: true };
    const outcome = await gated(request, verified);
    if (row.action === 'block' && outcome.decision === 'deny') counts.attackDenied++;
    if (row.action === 'alert' && outcome.decision === 'deny') counts.ambiguousDenied++;
    if (row.action === 'record' && outcome.decision === 'deny') counts.normalDenied++;
    const later = await gated({ ...request, at: new Date(Date.parse(at) + 16 * 60000).toISOString() }, verified);
    if (later.decision === 'deny') counts.expiredDenied++;
    // 확인되지 않은 주소와 브라우저가 보낸 값은 차단 근거가 아니다.
    assert.equal((await gated(request, { destinationIp: alert.data.dstip, destinationVerified: false })).decision, 'allow');
    assert.equal((await gated(request, {})).decision, 'allow');
  }
  assert.deepEqual(counts, { attackDenied: 8, normalDenied: 0, ambiguousDenied: 0, expiredDenied: 0 });
  const denied = await gated({ requestId: 'r', at: new Date(Date.parse(fixture.alerts[0].timestamp) + 1000).toISOString() },
    { destinationIp: fixture.alerts[0].data.dstip, destinationVerified: true });
  assert.deepEqual(Object.keys(denied).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
  assert.equal(denied.reasonCode, 'xdr_blocked');
});

test('exfiltration never makes a rule for internal addresses or for a destination that normal events also use', async () => {
  for (const ip of ['10.0.0.5', '192.168.1.9', '172.16.4.4', '127.0.0.1', '169.254.1.1', '100.64.0.1', 'fe80::1', '::1', 'not-an-ip', undefined]) {
    assert.equal(isBlockableDestination(ip), false, String(ip));
  }
  assert.equal(isBlockableDestination('203.0.113.51'), true);
  const clone = JSON.parse(JSON.stringify(fixture));
  clone.alerts[0].data.dstip = '10.1.2.3';
  clone.alerts[1].data.dstip = clone.alerts[16].data.dstip; // 정상 이벤트(ex-17)가 쓰는 목적지
  const rules = await respond(await mkdtemp(join(tmpdir(), 'ex-guard-')), clone,
    { ...result, decisions: clone.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) })) });
  const blocked = rules.map(rule => rule.evidenceAlertId);
  assert.ok(!blocked.includes('ex-01') && !blocked.includes('ex-02'));
  assert.equal(rules.length, 6);
});
