import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { readAlerts, redact } from '../xdr/brute-force/read-alerts.mjs';
import { decide } from '../xdr/brute-force/decide.mjs';
import { runBruteForce } from '../xdr/brute-force/run.mjs';
import { createBridge } from '../xdr/brute-force/bridge.mjs';
import { bruteForceStep } from '../xdr/brute-force/gate.mjs';

const fixture = new URL('../xdr/fixtures/brute-force.json', import.meta.url);
const weak = { outcome: 'failure', level: 5, description: 'sshd: authentication failed.',
  context: { rapid: { windowSeconds: 120, failuresSameAccount: 6 }, spray: { windowSeconds: 300, distinctAccounts: 1, failuresFromSource: 6 }, sharedAddress: false } };

test('reader keeps one row per alert, leaves the original untouched and hides secret-like values', async () => {
  const before = createHash('sha256').update(readFileSync(fixture)).digest('hex');
  const rows = await readAlerts(fixture);
  assert.equal(rows.length, JSON.parse(readFileSync(fixture, 'utf8')).length);
  assert.equal(createHash('sha256').update(readFileSync(fixture)).digest('hex'), before);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['account', 'alertId', 'at', 'description', 'level', 'srcip']);
  const text = JSON.stringify(rows);
  assert.equal(text.includes('FAKE-TEST-TOKEN'), false);
  assert.match(redact('password=abc123 and Bearer abcdefghijklmnop'), /\[가림\]/u);
});

test('decide: strong block, Jev-scored weak cases, no Jev falls back to alert, normal is record', async () => {
  const strong = { ...weak, context: { ...weak.context, rapid: { windowSeconds: 120, failuresSameAccount: 12 } } };
  assert.equal((await decide(strong)).action, 'block');
  assert.equal((await decide(weak, { askJev: async () => 0.9 })).action, 'block');
  assert.equal((await decide(weak, { askJev: async () => 0.6 })).action, 'alert');
  assert.equal((await decide(weak, { askJev: async () => 0.2 })).action, 'record');
  for (const askJev of [async () => null, async () => { throw new Error('down'); }, async () => 'x', () => new Promise(() => {})]) {
    const out = await decide(weak, { askJev, timeoutMs: 20 });
    assert.equal(out.action, 'alert');
    assert.match(out.reason, /^rapid_failed_logins:/u);
  }
  assert.deepEqual(Object.keys(await decide(weak, { askJev: async () => 0.6 })).sort(), ['action', 'confidence', 'reason']);
  assert.equal((await decide({ outcome: 'success', description: 'ok', context: null })).action, 'record');
});

test('fixture run: attacks blocked, ambiguous only alerted, normal never blocked', async () => {
  const { result, rules, logLines } = await runBruteForce();
  assert.equal(result.alertCount, result.extractedRows);
  assert.equal(result.counts.block + result.counts.alert + result.counts.record, result.alertCount);
  assert.deepEqual(result.normalBlocked, []);
  assert.equal(result.byLabel.ambiguous.block, 0);
  assert.ok(result.byLabel.attack.block > 0);
  assert.equal(result.replay.blocked.normal, 0);
  assert.ok(rules.length >= 1 && rules.every((r) => r.expiresAt && r.evidenceAlertIds.length > 0));
  assert.ok(logLines.length > 0);
  const eager = await runBruteForce({ askJev: async () => 0.9 });
  assert.deepEqual(eager.result.normalBlocked, []);
  assert.ok(eager.result.byLabel.normal.block === 0);
});

test('bridge refuses internal and allow-listed addresses and the gate never allows', () => {
  const bridge = createBridge({ allowlist: ['203.0.113.99'] });
  const decision = { action: 'block', confidence: 0.95, reason: 'rapid_failed_logins: x' };
  for (const srcip of ['10.1.2.3', '127.0.0.1', '203.0.113.99', null]) {
    assert.equal(bridge.handle({ alertId: 'a', at: '2026-10-07T00:00:00.000Z', srcip, account: 'x' }, decision).action, 'alert');
  }
  assert.equal(bridge.rules().length, 0);
  bridge.handle({ alertId: 'b', at: '2026-10-07T00:00:00.000Z', srcip: '203.0.113.5', account: 'x' }, decision);
  const [rule] = bridge.rules();
  assert.equal(Date.parse(rule.expiresAt) - Date.parse(rule.createdAt), 3600000);
  const at = Date.parse('2026-10-07T00:10:00.000Z');
  const sourceOf = () => ({ srcip: '203.0.113.5' });
  assert.equal(bruteForceStep({}, { rules: bridge.rules(), now: at, sourceOf }).hit, true);
  assert.equal(bruteForceStep({}, { rules: bridge.rules(), now: Date.parse('2026-10-07T02:00:00.000Z'), sourceOf }), null);
  assert.equal(bruteForceStep({}, { rules: bridge.rules(), now: at }), null);
});

test('decide also works on raw Wazuh alerts fed one by one, and trusts Wazuh correlation alerts', async () => {
  const { decide: d, resetState } = await import('../xdr/brute-force/decide.mjs');
  const alerts = JSON.parse(readFileSync(fixture, 'utf8'));
  const labels = JSON.parse(readFileSync(new URL('../xdr/fixtures/brute-force.labels.json', import.meta.url), 'utf8'));
  resetState();
  const seen = { block: 0, alert: 0, record: 0 };
  for (const alert of alerts) {
    const out = await d(alert);
    seen[out.action] += 1;
    if (labels[alert.id] === 'normal') assert.notEqual(out.action, 'block', alert.id);
  }
  assert.ok(seen.block > 0 && seen.alert > 0 && seen.record > 0);
  assert.equal((await d(alerts[0])).action !== undefined, true);
  resetState();
  const correlated = { timestamp: '2026-10-07T03:00:00.000+0000', id: 'c1', rule: { id: '5712', level: 10, description: 'sshd: brute force trying to get access to the system. Authentication failed.' }, data: { srcip: '203.0.113.50', dstuser: 'root' } };
  const out = await d(correlated);
  assert.equal(out.action, 'block');
  assert.match(out.reason, /^wazuh_correlated_bruteforce:/u);
  resetState();
});
