import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/persistence/decide.mjs';
import { readAlerts } from '../xdr/persistence/read-alerts.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('../', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));
const outcomes = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));

test('persistence decide is standalone and independent of event IDs, IPs, order and timestamps', async () => {
  const code = await readFile(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(code, /\bimport\s|\bfetch\s*\(|\bprocess\.|\brequire\(/u);
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
  for (const alert of [...fixture.alerts].reverse()) {
    const renamed = { ...alert, id: 'independent-event', timestamp: '2026-10-13T03:00:00Z',
      data: { ...alert.data, srcip: '192.0.2.200' } };
    assert.deepEqual(isolated.decide(renamed), decide(alert));
    assert.deepEqual(Object.keys(decide(alert)).sort(), ['action', 'confidence', 'reason']);
  }
});

test('persistence separates clear attacks, ambiguous attempts and normal events', () => {
  const ids = action => outcomes.filter(row => row.action === action).map(row => row.alertId);
  assert.deepEqual(ids('block'), ['ps-01', 'ps-02', 'ps-03', 'ps-04', 'ps-05', 'ps-06', 'ps-07', 'ps-08']);
  assert.deepEqual(ids('alert'), ['ps-09', 'ps-10', 'ps-11', 'ps-12', 'ps-13', 'ps-14', 'ps-15', 'ps-16']);
  assert.deepEqual(ids('record'), ['ps-17', 'ps-18', 'ps-19', 'ps-20', 'ps-21', 'ps-22', 'ps-23', 'ps-24']);
  // 수준만 높고 근거가 하나도 없으면 차단하지 않는다.
  const weak = fixture.alerts.find(alert => alert.id === 'ps-11');
  assert.equal(decide({ ...weak, rule: { ...weak.rule, level: 15 } }).action, 'alert');
  assert.equal(decide(null).action, 'alert');
});

test('persistence reasons never echo paths, source addresses or request-like values', () => {
  for (const alert of fixture.alerts) {
    const row = decide(alert);
    assert.ok(Number.isFinite(row.confidence) && row.confidence >= 0 && row.confidence <= 1);
    assert.equal(row.action, row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(!row.reason.includes(alert.data.srcip));
    if (alert.data.path) assert.ok(!row.reason.includes(alert.data.path));
    assert.ok(!row.reason.includes(alert.data.srcuser));
  }
});

test('persistence pattern file matches the constants used by decide', async () => {
  const patterns = JSON.parse(await readFile(new URL('../xdr/persistence/patterns.json', import.meta.url), 'utf8'));
  const code = await readFile(new URL('../xdr/persistence/decide.mjs', import.meta.url), 'utf8');
  const inspect = await import(`data:text/javascript;base64,${Buffer.from(`${code}\nexport { PATTERNS };`).toString('base64')}`);
  assert.deepEqual(inspect.PATTERNS.map(p => p.name), patterns.patterns.map(p => p.name));
  for (const pattern of patterns.patterns) {
    assert.ok(pattern.condition);
    assert.ok(pattern.evidence);
    assert.ok(pattern.sources.length);
  }
});

test('persistence reader projects one safe row per original event', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  for (const row of rows) {
    assert.deepEqual(Object.keys(row).sort(), ['account', 'description', 'level', 'sourceIp', 'timestamp']);
  }
});

test('persistence run writes a result with counts that match decide', async () => {
  const result = await runXdr({ root: fileURLToPath(root), moduleKey: 'persistence' });
  assert.equal(result.schema, 'aleph.xdr.result.v1');
  assert.deepEqual(result.counts, { block: 8, alert: 8, record: 8 });
});
