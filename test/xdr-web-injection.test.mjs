import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { decide } from '../xdr/web-injection/decide.mjs';
import { readAlerts, redact } from '../xdr/web-injection/read-alerts.mjs';
import { applyActions } from '../xdr/web-injection/apply-actions.mjs';
import { applyActions as applyBrute } from '../xdr/brute-force/apply-actions.mjs';
import { webInjectionStep } from '../xdr/web-injection/gate.mjs';

const fixtureUrl = new URL('../xdr/fixtures/web-injection.json', import.meta.url);
const alerts = JSON.parse(readFileSync(fixtureUrl, 'utf8')).alerts;
const source = readFileSync(new URL('../xdr/web-injection/decide.mjs', import.meta.url), 'utf8');
const patterns = JSON.parse(readFileSync(new URL('../xdr/web-injection/patterns.json', import.meta.url), 'utf8'));

test('읽기 모듈: 경보 건수와 뽑은 줄 수가 같고 다섯 값만 뽑으며 원본을 고치지 않는다', async () => {
  const before = JSON.stringify(alerts);
  const rows = await readAlerts(fixtureUrl);
  assert.equal(rows.length, alerts.length);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['account', 'alertId', 'at', 'description', 'level', 'srcip']);
  assert.equal(JSON.stringify(alerts), before);
  assert.equal(JSON.stringify(rows).includes('/notes?q='), false);
  assert.match(redact('token=abc123 Bearer abcdefghijklmnop'), /\[가림\]/u);
  assert.equal((await readAlerts(alerts)).length, alerts.length);
});

test('패턴 목록: 모두 T1190 근거와 조건이 한 줄씩 있다', () => {
  assert.ok(patterns.patterns.length >= 3);
  for (const p of patterns.patterns) {
    assert.ok(p.name && p.condition && p.evidence, p.id);
    assert.equal(p.mitre.id, 'T1190');
  }
});

test('판정: 명확한 공격 8건 block, 애매한 9건 alert, 정상 9건 record', async () => {
  const counts = { block: 0, alert: 0, record: 0 };
  const ids = patterns.patterns.map((p) => p.id);
  for (const [i, alert] of alerts.entries()) {
    const out = await decide(alert);
    counts[out.action] += 1;
    assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
    if (i < 8) { assert.equal(out.action, 'block'); assert.ok(ids.some((id) => out.reason.startsWith(id))); }
    else if (i < 17) assert.equal(out.action, 'alert');
    else assert.equal(out.action, 'record');
  }
  assert.deepEqual(counts, { block: 8, alert: 9, record: 9 });
});

test('decide.mjs 는 단일 파일이라 격리된 환경에서도 같은 결과를 낸다', async () => {
  assert.equal(/^\s*import\s/mu.test(source), false);
  assert.equal((source.match(/^export /gmu) ?? []).length, 1);
  const isolated = runInNewContext(source.replace('export async function decide', 'async function decide') + '\n;decide;', {}, { timeout: 1000 });
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of alerts) counts[(await isolated(alert)).action] += 1;
  assert.deepEqual(counts, { block: 8, alert: 9, record: 9 });
});

test('입력 모양이 달라도 명확한 공격을 놓치지 않고, 평범한 반복 요청이나 한 번의 의심은 막지 않는다', async () => {
  for (const alert of alerts.slice(0, 8)) {
    const s = structuredClone(alert);
    s.rule.level = String(alert.rule.level);
    assert.equal((await decide(s)).action, 'block');
    const flat = { sourceIp: alert.data.srcip, level: String(alert.rule.level), description: alert.rule.description, count: alert.data.count };
    assert.equal((await decide(flat)).action, 'block');
  }
  assert.notEqual((await decide({ level: 12, count: 100, description: '자료 목록 조회' })).action, 'block');
  assert.notEqual((await decide({ level: 12, count: 1, description: 'SQL 주입 의심' })).action, 'block');
  assert.notEqual((await decide({ level: 12, count: 20, description: '삽입 표식은 아닙니다. 스크립트라는 수업 단어가 20번 있습니다.' })).action, 'block');
  assert.equal((await decide({})).action, 'record');
});

test('애매한 경보: Jev 확신도에 따라 나뉘고 응답이 없으면 alert', async () => {
  const weak = { level: 6, count: 1, description: '검색어에 따옴표가 한 번 들어 있습니다.' };
  assert.equal((await decide(weak, { askJev: async () => 0.9 })).action, 'block');
  assert.equal((await decide(weak, { askJev: async () => 0.6 })).action, 'alert');
  assert.equal((await decide(weak, { askJev: async () => 0.2 })).action, 'record');
  for (const askJev of [async () => null, async () => { throw new Error('x'); }, async () => 'bad', () => new Promise(() => {})]) {
    assert.equal((await decide(weak, { askJev, timeoutMs: 20 })).action, 'alert');
  }
});

test('원본 경보의 요청 주소를 보고, 같은 주소에서 반복될 때만 block 하며 주소 값은 reason 에 남기지 않는다', async () => {
  const mk = (n, srcip, url) => ({ id: `raw-${srcip}-${n}`, timestamp: `2026-10-07T03:00:${String(n * 5).padStart(2, '0')}+0000`,
    rule: { level: 6, description: 'web request' }, data: { srcip, url } });
  const bad = "/notes?q=1'%20UNION%20SELECT%20password%20FROM%20users--";
  const out = [];
  for (let n = 1; n <= 6; n += 1) out.push(await decide(mk(n, '203.0.113.77', bad)));
  assert.equal(out[0].action, 'alert');
  assert.equal(out[5].action, 'block');
  assert.equal(JSON.stringify(out).includes('UNION'), false);
  for (let n = 1; n <= 6; n += 1) assert.equal((await decide(mk(n, '203.0.113.88', '/search?q=select-course'))).action, 'record');
});

test('거부 규칙: 명확한 공격 주소만, 만료 시각·근거 경보 번호와 함께. 알림은 모듈별로 쌓인다', async () => {
  const root = await mkdtemp(join(tmpdir(), 'xdr-web-'));
  try {
    const decisions = [];
    for (const alert of alerts) decisions.push({ alertId: alert.id, ...(await decide(alert)) });
    const rules = await applyActions({ root, alerts, decisions });
    const attackIps = new Set(alerts.slice(0, 8).map((a) => a.data.srcip));
    const normalIps = new Set(alerts.slice(8).map((a) => a.data.srcip));
    assert.ok(rules.length >= 1);
    for (const rule of rules) {
      assert.ok(attackIps.has(rule.sourceIp) && !normalIps.has(rule.sourceIp));
      assert.ok(Date.parse(rule.expiresAt) > Date.now() && rule.evidenceAlertId);
    }
    await applyBrute({ root, alerts: [], decisions: [{ alertId: 'b1', action: 'alert', confidence: 0.5, reason: 'x' }] });
    const lines = (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n').map((l) => JSON.parse(l));
    assert.ok(lines.some((l) => l.module === 'web-injection') && lines.some((l) => l.module === 'brute-force'));
    await applyActions({ root, alerts, decisions });
    const again = (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n');
    assert.equal(again.length, lines.length);
    const internal = await applyActions({ root, alerts: [{ id: 'i1', data: { srcip: '10.0.0.5' } }], decisions: [{ alertId: 'i1', action: 'block', confidence: 0.9, reason: 't' }] });
    assert.equal(internal.length, 0);
    const hit = webInjectionStep({}, { rules, sourceOf: () => ({ srcip: rules[0].sourceIp }) });
    assert.equal(hit.hit, true);
    assert.equal(webInjectionStep({}, { rules, sourceOf: () => ({ srcip: '192.0.2.70' }) }), null);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
