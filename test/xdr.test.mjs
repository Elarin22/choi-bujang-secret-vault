import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide as brute, setJevReviewer } from '../xdr/brute-force/decide.mjs';
import { decide as web } from '../xdr/web-injection/decide.mjs';
import { readAlerts as readBrute } from '../xdr/brute-force/read-alerts.mjs';
import { readAlerts as readWeb } from '../xdr/web-injection/read-alerts.mjs';
import { projectAlert } from '../xdr/read-alerts.mjs';
import { decision } from '../xdr/jev.mjs';
import { ruleFor, withXdr } from '../xdr/ztna-overlay.mjs';

const sample = ({ level = 12, description, count, url, accounts } = {}) => ({
  id: 'test-event', timestamp: '2026-10-07T10:00:00Z',
  rule: { level, description, mitre: [] },
  data: { srcip: '192.0.2.90', srcuser: 'user01', count, url, accounts },
});
test('submitted deciders execute as isolated modules without repository imports', async () => {
  for (const key of ['brute-force', 'web-injection']) {
    const code = await readFile(new URL(`../xdr/${key}/decide.mjs`, import.meta.url), 'utf8');
    assert.doesNotMatch(code, /^import\s/mu);
    const isolated = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
    const fixture = JSON.parse(await readFile(new URL(`../xdr/fixtures/${key}.json`, import.meta.url), 'utf8'));
    const local = key === 'brute-force' ? brute : web;
    for (const alert of fixture.alerts) assert.deepEqual(await isolated.decide(alert), await local(alert));
  }
});
test('reader preserves every row and projects only five safe fields', async () => {
  for (const [key, reader] of [['brute-force', readBrute], ['web-injection', readWeb]]) {
    const fixture = JSON.parse(await readFile(new URL(`../xdr/fixtures/${key}.json`, import.meta.url), 'utf8'));
    const rows = await reader();
    assert.equal(rows.length, fixture.alerts.length);
    assert.deepEqual(Object.keys(rows[0]).sort(), ['account', 'description', 'level', 'sourceIp', 'timestamp']);
  }
  const secret = ['sb', 'secret', 'this_is_a_synthetic_fixture_value'].join('_');
  const row = projectAlert({ ...sample({ description: `password=fictional ${secret}` }), data: { srcip: '192.0.2.90', srcuser: 'fictional-account' } });
  assert.ok(!row.description.includes(secret)); assert.ok(!row.description.includes('fictional'));
  assert.ok(row.account.startsWith('account-'));
});
test('brute-force requires correlated failure evidence and keeps normal events', async () => {
  assert.equal((await brute(sample({ description: '같은 주소에서 2분 안에 로그인 실패 48건이 쌓였습니다.', count: '48' }))).action, 'block');
  assert.equal((await brute(sample({ description: '한 계정에 10분 동안 로그인 실패 50건입니다.', count: '50' }))).action, 'alert');
  assert.equal((await brute(sample({ level: 3, description: '로그인 실패 1건 뒤에 성공했습니다.', count: '1' }))).action, 'record');
  assert.equal((await brute(sample({ level: 12, description: '자료 목록 조회', count: '100' }))).action, 'alert');
  assert.equal((await brute(sample({ description: '여러 계정에 같은 비밀번호를 연속으로 넣었습니다.', accounts: 'user01,user02,user03,user04,user05,user06' }))).action, 'block');
});
test('web detects encoded structures and requires repetition before local block', async () => {
  assert.equal((await web(sample({ description: '주입 구조 반복', count: '9', url: '/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E' }))).action, 'block');
  assert.equal((await web(sample({ level: 8, description: '한 번의 요청', count: '1', url: '/?p=../../notes' }))).action, 'alert');
  assert.equal((await web(sample({ level: 3, description: '수업 공지 조회', url: '/?q=select-script-course' }))).action, 'record');
  assert.equal((await web(sample({ level: 12, description: '정상 조회', count: '30', url: '/api/notes' }))).action, 'alert');
});
test('Jev only receives ambiguous sanitized facts; unavailable is alert', async () => {
  const ambiguous = sample({ level: 6, description: '로그인 실패 4건', count: '4' });
  let calls = 0;
  try {
    setJevReviewer(async facts => { calls++; assert.deepEqual(Object.keys(facts).sort(), ['count', 'level', 'pattern']); return { confidence: 0.9 }; });
    assert.equal((await brute(ambiguous)).action, 'block');
    await brute(sample({ description: '로그인 실패 50건', count: '50' }));
    await brute(sample({ level: 2, description: '로그인 성공' }));
    assert.equal(calls, 1);
    setJevReviewer(async () => { throw new Error('not available'); });
    assert.equal((await brute(ambiguous)).action, 'alert');
    setJevReviewer(async () => ({ confidence: NaN }));
    assert.equal((await brute(ambiguous)).action, 'alert');
    assert.equal(decision(0.85, 'test').action, 'block');
    assert.equal(decision(0.5, 'test').action, 'alert');
    assert.equal(decision(0.49, 'test').action, 'record');
  } finally { setJevReviewer(); }
});
test('overlay preserves base policy, rejects unverified IP and expires', async () => {
  const alert = sample({ description: '로그인 실패 50건', count: '50' });
  const rule = ruleFor(alert, await brute(alert), 'brute-force');
  assert.equal(rule.evidenceAlertId, alert.id);
  assert.equal(ruleFor(alert, { action: 'alert', confidence: 0.5 }, 'brute-force'), null);
  const base = async req => ({ schema: 'aleph.decision.v1', requestId: req.requestId, decision: 'allow', reasonCode: 'test_baseline', ruleIds: [] });
  const gate = withXdr(base, [rule]);
  const req = { requestId: 'test-request', at: '2026-10-07T10:01:00Z' };
  assert.equal((await gate(req, { sourceVerified: true, sourceIp: '192.0.2.90' })).decision, 'deny');
  assert.deepEqual(await gate(req, { sourceVerified: false, sourceIp: '192.0.2.90' }), await base(req));
  assert.deepEqual(await gate(req, { sourceVerified: true, sourceIp: '192.0.2.91' }), await base(req));
  assert.deepEqual(await gate({ ...req, at: '2026-10-07T10:15:00Z' }, { sourceVerified: true, sourceIp: '192.0.2.90' }), await base({ ...req, at: '2026-10-07T10:15:00Z' }));
});
