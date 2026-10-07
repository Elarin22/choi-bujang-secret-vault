import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { decide } from '../xdr/brute-force/decide.mjs';
import { readAlerts, redact } from '../xdr/brute-force/read-alerts.mjs';
import { applyActions } from '../xdr/brute-force/apply-actions.mjs';
import { bruteForceStep } from '../xdr/brute-force/gate.mjs';

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const official = read('../xdr/fixtures/brute-force.json').alerts;
const sequence = read('../xdr/fixtures/practice/brute-force-sequence.json');
const labels = read('../xdr/fixtures/practice/brute-force-sequence.labels.json');
const source = readFileSync(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');

test('공식 형식 경보: 명확한 공격 10건 block, 애매한 9건 alert, 정상 9건 record', async () => {
  const counts = { block: 0, alert: 0, record: 0 };
  const out = [];
  for (const alert of official) { const r = await decide(alert); out.push(r); counts[r.action] += 1; }
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
  out.forEach((r, i) => {
    assert.deepEqual(Object.keys(r).sort(), ['action', 'confidence', 'reason']);
    if (i >= 19) assert.equal(r.action, 'record');
    if (i < 10) assert.equal(r.action, 'block');
  });
});

test('decide.mjs 는 다른 파일 없이 격리된 환경에서도 돈다', async () => {
  assert.equal(/^\s*import\s/mu.test(source), false);
  assert.equal((source.match(/^export /gmu) ?? []).length, 1);
  const isolated = runInNewContext(source.replace('export async function decide', 'async function decide') + '\n;decide;', {}, { timeout: 1000 });
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of official) counts[(await isolated(alert)).action] += 1;
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
});

test('입력 모양이 달라도 명확한 공격을 놓치지 않는다', async () => {
  for (const alert of official.slice(0, 10)) {
    const stringLevel = structuredClone(alert);
    stringLevel.rule.level = String(alert.rule.level);
    assert.equal((await decide(stringLevel)).action, 'block');
    const flat = { sourceIp: alert.data.srcip, level: String(alert.rule.level), description: alert.rule.description,
      count: alert.data.count, accounts: alert.data.accounts };
    assert.equal((await decide(flat)).action, 'block');
  }
  assert.equal((await decide({ level: '12', count: 60, description: '로그인 실패 60건 뒤에 성공했습니다.' })).action, 'block');
  assert.equal((await decide({ level: '3', count: 1, description: '로그인 실패 1건 뒤에 성공했습니다.' })).action, 'record');
  assert.equal((await decide({})).action, 'record');
});

test('애매한 경보: Jev 확신도에 따라 나뉘고, 응답이 없으면 alert', async () => {
  const weak = { level: 6, count: 4, description: '같은 계정 로그인 실패 4건 뒤에 성공했습니다.' };
  assert.equal((await decide(weak, { askJev: async () => 0.9 })).action, 'block');
  assert.equal((await decide(weak, { askJev: async () => 0.6 })).action, 'alert');
  assert.equal((await decide(weak, { askJev: async () => 0.2 })).action, 'record');
  for (const askJev of [async () => null, async () => { throw new Error('down'); }, async () => 'x', () => new Promise(() => {})]) {
    assert.equal((await decide(weak, { askJev, timeoutMs: 20 })).action, 'alert');
  }
});

test('한 줄씩 들어오는 Wazuh 원본 경보: 공격은 막고 정상은 막지 않는다', async () => {
  const seen = { block: 0, alert: 0, record: 0 };
  for (const alert of sequence) {
    const out = await decide(alert);
    seen[out.action] += 1;
    if (labels[alert.id] === 'normal') assert.notEqual(out.action, 'block', alert.id);
    if (labels[alert.id] === 'ambiguous') assert.notEqual(out.action, 'block', alert.id);
  }
  assert.ok(seen.block >= 20 && seen.alert > 0 && seen.record > 0, JSON.stringify(seen));
});

test('reader 는 경보마다 한 줄을 만들고 비밀값처럼 보이는 값을 가린다', async () => {
  const rows = await readAlerts(new URL('../xdr/fixtures/practice/brute-force-sequence.json', import.meta.url));
  assert.equal(rows.length, sequence.length);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['account', 'alertId', 'at', 'description', 'level', 'srcip']);
  assert.match(redact('password=abc123 and Bearer abcdefghijklmnop'), /\[가림\]/u);
});

test('거부 규칙에는 만료 시각·근거 경보 번호가 있고 이번 실행 시각 이후까지 유효하다', async () => {
  const root = await mkdtemp(join(tmpdir(), 'xdr-brute-'));
  try {
    const decisions = [];
    for (const alert of official) decisions.push({ alertId: alert.id, ...(await decide(alert)) });
    const rules = await applyActions({ root, alerts: official, decisions });
    assert.ok(rules.length >= 1);
    const blockIds = new Set(decisions.filter((d) => d.action === 'block').map((d) => d.alertId));
    for (const rule of rules) {
      assert.ok(Date.parse(rule.expiresAt) > Date.now());
      assert.ok(rule.evidenceAlertId && rule.evidenceAlertIds.every((id) => blockIds.has(id)));
    }
    const internal = [{ id: 'x1', data: { srcip: '10.1.2.3' } }];
    const none = await applyActions({ root, alerts: internal, decisions: [{ alertId: 'x1', action: 'block', confidence: 0.9, reason: 't' }] });
    assert.equal(none.length, 0);
    const step = bruteForceStep({}, { rules: [{ id: 'r', effect: 'deny', match: { srcip: '203.0.113.5' }, createdAt: '2026-10-07T00:00:00Z',
      expiresAt: '2026-10-07T01:00:00Z', evidenceAlertIds: ['a'] }], now: Date.parse('2026-10-07T00:10:00Z'), sourceOf: () => ({ srcip: '203.0.113.5' }) });
    assert.equal(step.hit, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
