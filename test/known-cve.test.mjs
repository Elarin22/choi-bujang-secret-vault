import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile, writeFile, mkdir, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/known-cve/decide.mjs';
import { readAlerts } from '../xdr/known-cve/read-alerts.mjs';
import { respond, connectDecider } from '../xdr/known-cve/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));
const outcomes = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
const result = { schema: 'aleph.xdr.result.v1', moduleKey: 'known-cve', decisions: outcomes };
const attack = fixture.alerts.find(alert => decide(alert).action === 'block');
const normal = fixture.alerts.find(alert => decide(alert).action === 'record');

test('known-cve is standalone and independent of event IDs, IPs, order and timestamps', async () => {
  const code = await readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(code, /\bimport\s|\bfetch\s*\(|\bprocess\./u);
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
  for (const alert of [...fixture.alerts].reverse()) {
    const renamed = { ...alert, id: 'independent-event', timestamp: '2026-10-13T03:00:00Z',
      data: { ...alert.data, srcip: '192.0.2.200' } };
    assert.deepEqual(isolated.decide(renamed), decide(alert));
    assert.deepEqual(Object.keys(decide(alert)).sort(), ['action', 'confidence', 'reason']);
  }
});
test('known-cve separates complete request structure, contextual warnings and normal events', () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const row of outcomes) counts[row.action]++;
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  assert.equal(decide({ ...normal, rule: { ...normal.rule, level: 15 } }).action, 'alert');
  assert.equal(decide({ ...normal, rule: attack.rule }).action, 'alert');
  const originalLookup = attack.data.useragent ?? attack.data.url;
  assert.equal(decide({ ...normal, data: { ...normal.data, headers: { 'User-Agent': originalLookup } } }).action, 'block');
  assert.equal(decide({ ...normal, data: { ...normal.data, params: { q: originalLookup } } }).action, 'block');
  // Deleting the request structure removes the only block evidence.
  assert.equal(decide({ ...attack, data: { srcip: attack.data.srcip } }).action, 'alert');
  assert.equal(decide(null).action, 'alert');
  const changed = { ...normal, data: { ...normal.data, headers: [null, {}, 1] } };
  assert.equal(decide(changed).action, 'record');
});
test('known-cve pattern file matches submitted constants and never echoes request material', async () => {
  const patterns = JSON.parse(await readFile(new URL('../xdr/known-cve/patterns.json', import.meta.url), 'utf8'));
  const code = await readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');
  const inspect = await import(`data:text/javascript;base64,${Buffer.from(`${code}\nexport { PATTERNS };`).toString('base64')}`);
  assert.deepEqual(inspect.PATTERNS, patterns.map(({ name, regex, confidence }) => ({ name, regex, confidence })));
  for (const pattern of patterns) { assert.ok(pattern.condition); assert.ok(pattern.evidence); assert.ok(pattern.sources.length); }
  for (const alert of fixture.alerts) {
    const row = decide(alert);
    assert.ok(Number.isFinite(row.confidence) && row.confidence >= 0 && row.confidence <= 1);
    assert.equal(row.action, row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(!row.reason.includes(alert.data.srcip));
    if (alert.data.url) assert.ok(!row.reason.includes(alert.data.url));
  }
});
test('known-cve reader projects one safe row per original event', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  for (const row of rows) assert.deepEqual(Object.keys(row).sort(), ['account', 'description', 'level', 'sourceIp', 'timestamp']);
});
test('known-cve responder persists only block candidates, preserves other modules and deduplicates alerts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aleph-known-cve-'));
  await mkdir(join(root, 'xdr'));
  const other = { id: 'other-module', moduleKey: 'web-injection' };
  await writeFile(join(root, 'xdr', 'deny-rules.json'), JSON.stringify({ rules: [other] }));
  const rules = await respond(root, fixture, result);
  assert.equal(rules.length, 8);
  for (const rule of rules) {
    assert.equal(rule.moduleKey, 'known-cve');
    assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.issuedAt), 15 * 60000);
    assert.equal(outcomes.find(row => row.alertId === rule.evidenceAlertId).action, 'block');
    assert.equal(rule.reason, 'kc_remote_lookup');
  }
  await respond(root, fixture, result);
  const stored = JSON.parse(await readFile(join(root, 'xdr', 'deny-rules.json'), 'utf8'));
  assert.deepEqual(stored.rules.find(rule => rule.id === other.id), other);
  assert.equal(stored.rules.length, 9);
  const logs = (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(logs.length, 16);
  assert.ok(logs.every(row => row.action !== 'record' && /^kc_\w+$/u.test(row.reason)));
  assert.ok(logs.every(row => Object.keys(row).sort().join(',') === 'action,alertId,confidence,moduleKey,reason'));
  const bad = { ...result, decisions: outcomes.map((row, index) => index ? row : { ...row, confidence: NaN }) };
  await assert.rejects(respond(root, fixture, bad), /判定|판정/u);
  const baseline = async request => ({ schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'allow', reasonCode: 'test_baseline', ruleIds: [] });
  const gated = connectDecider(baseline, rules);
  const replay = { attackDenied: 0, normalDenied: 0, ambiguousDenied: 0 };
  for (const alert of fixture.alerts) {
    const request = { requestId: alert.id, at: new Date(Date.parse(alert.timestamp) + 1000).toISOString() };
    const observed = await gated(request, { sourceVerified: true, sourceIp: alert.data.srcip });
    if (observed.decision === 'deny') replay[decide(alert).action === 'block' ? 'attackDenied'
      : decide(alert).action === 'alert' ? 'ambiguousDenied' : 'normalDenied']++;
    assert.deepEqual(await gated(request, { sourceVerified: false, sourceIp: alert.data.srcip }), await baseline(request));
  }
  assert.deepEqual(replay, { attackDenied: 8, normalDenied: 0, ambiguousDenied: 0 });
  const rule = rules[0];
  const expired = { requestId: 'expired', at: new Date(Math.max(...rules
    .filter(item => item.sourceIp === rule.sourceIp).map(item => Date.parse(item.expiresAt)))).toISOString() };
  assert.deepEqual(await gated(expired, { sourceVerified: true, sourceIp: rule.sourceIp }), await baseline(expired));
  const rejectingBase = async request => ({ ...await baseline(request), decision: 'deny', reasonCode: 'existing_policy' });
  const request = { requestId: 'normal', at: normal.timestamp };
  assert.deepEqual(await connectDecider(rejectingBase, rules)(request, { sourceVerified: true, sourceIp: normal.data.srcip }),
    await rejectingBase(request));
});
test('known-cve official runner computes all results without stored answers', async () => {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const errors = [];
  const computed = await runXdr({ root, moduleKey: 'known-cve', writeError: line => errors.push(line) });
  assert.deepEqual(computed.counts, { block: 8, alert: 8, record: 8 });
  assert.deepEqual(computed.decisions, outcomes);
  assert.deepEqual(errors, []);
});
