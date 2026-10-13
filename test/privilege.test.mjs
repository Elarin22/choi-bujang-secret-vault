import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/privilege/decide.mjs';
import { readAlerts } from '../xdr/privilege/read-alerts.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = new URL('../', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json', import.meta.url), 'utf8'));
const outcomes = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));

test('privilege decide is standalone and independent of event IDs, IPs, order and timestamps', async () => {
  const code = await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(code, /\bimport\s|\bfetch\s*\(|\bprocess\.|\brequire\(/u);
  const isolated = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
  for (const alert of [...fixture.alerts].reverse()) {
    const renamed = { ...alert, id: 'independent-event', timestamp: '2026-10-13T03:00:00Z',
      data: { ...alert.data, srcip: '192.0.2.200' } };
    assert.deepEqual(isolated.decide(renamed), decide(alert));
    assert.deepEqual(Object.keys(decide(alert)).sort(), ['action', 'confidence', 'reason']);
  }
});

test('privilege separates clear attacks, ambiguous attempts and normal events', () => {
  const ids = action => outcomes.filter(row => row.action === action).map(row => row.alertId);
  const range = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => `pv-${String(from + i).padStart(2, '0')}`);
  assert.deepEqual(ids('block'), range(1, 9));
  assert.deepEqual(ids('alert'), range(10, 17));
  assert.deepEqual(ids('record'), range(18, 26));
  // 수준만 높고 근거가 하나도 없으면 차단하지 않는다.
  const weak = fixture.alerts.find(alert => alert.id === 'pv-10');
  assert.equal(decide({ ...weak, rule: { ...weak.rule, level: 15 } }).action, 'alert');
  assert.equal(decide(null).action, 'alert');
});

test('privilege reasons never echo paths, source addresses or request-like values', () => {
  for (const alert of fixture.alerts) {
    const row = decide(alert);
    assert.ok(Number.isFinite(row.confidence) && row.confidence >= 0 && row.confidence <= 1);
    assert.equal(row.action, row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(!row.reason.includes(alert.data.srcip));
    if (alert.data.path) assert.ok(!row.reason.includes(alert.data.path));
    assert.ok(!row.reason.includes(alert.data.srcuser));
  }
});

test('privilege pattern file matches the constants used by decide', async () => {
  const patterns = JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json', import.meta.url), 'utf8'));
  const code = await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');
  const inspect = await import(`data:text/javascript;base64,${Buffer.from(`${code}\nexport { PATTERNS };`).toString('base64')}`);
  assert.deepEqual(inspect.PATTERNS.map(p => p.name), patterns.patterns.map(p => p.name));
  for (const pattern of patterns.patterns) {
    assert.ok(pattern.condition);
    assert.ok(pattern.evidence);
    assert.ok(pattern.sources.length);
  }
});

test('privilege reader projects one safe row per original event', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  for (const row of rows) {
    assert.deepEqual(Object.keys(row).sort(), ['account', 'description', 'level', 'sourceIp', 'timestamp']);
  }
});

test('privilege run writes a result with counts that match decide', async () => {
  const result = await runXdr({ root: fileURLToPath(root), moduleKey: 'privilege' });
  assert.equal(result.schema, 'aleph.xdr.result.v1');
  assert.deepEqual(result.counts, { block: 9, alert: 8, record: 9 });
});
