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

test('persistence separates clear unsigned autostart events, weak evidence and normal events', () => {
  const blocked = outcomes.filter(row => row.action === 'block').map(row => row.alertId);
  assert.deepEqual(blocked, ['ps-01', 'ps-02', 'ps-03', 'ps-04', 'ps-05', 'ps-06']);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const row of outcomes) counts[row.action]++;
  assert.deepEqual(counts, { block: 6, alert: 5, record: 5 });
  // 운영 목록에 있는 서명 없는 항목과 문서 저장은 차단하지 않는다.
  for (const id of ['ps-12', 'ps-13', 'ps-14', 'ps-15', 'ps-16']) {
    assert.notEqual(outcomes.find(row => row.alertId === id).action, 'block');
  }
  // 수준이 높아도 자동 시작이 아니면 차단하지 않는다.
  const notAutostart = fixture.alerts.find(alert => alert.id === 'ps-07');
  assert.equal(decide({ ...notAutostart, rule: { ...notAutostart.rule, level: 15 } }).action, 'alert');
  assert.equal(decide(null).action, 'alert');
});

test('persistence reasons never echo paths, source addresses or request-like values', () => {
  for (const alert of fixture.alerts) {
    const row = decide(alert);
    assert.ok(Number.isFinite(row.confidence) && row.confidence >= 0 && row.confidence <= 1);
    assert.equal(row.action, row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(!row.reason.includes(alert.data.srcip));
    if (alert.data.path) assert.ok(!row.reason.includes(alert.data.path));
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
  assert.deepEqual(result.counts, { block: 6, alert: 5, record: 5 });
});
