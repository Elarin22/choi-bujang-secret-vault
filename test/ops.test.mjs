import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createDeviceService } from '../lib/device.mjs';
import { buildOpsSummary, createOpsHandler, loadInputs } from '../lib/ops-summary.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import { crossCheck, statusLabel, summaryRows } from '../public/ops-model.js';

const NOW = new Date('2026-10-13T00:00:00.000Z');
const call = async (handler, req) => {
  const out = { headers: {} };
  const res = { setHeader: (k, v) => { out.headers[k] = v; }, status: (c) => { out.code = c; return res; }, json: (b) => { out.body = b; return res; } };
  await handler({ headers: {}, ...req }, res);
  return out;
};
const summaryWith = async (adapter) => buildOpsSummary({ ...loadInputs(), device: await createDeviceService({ adapter, now: () => NOW }).status({}, null), now: NOW });

test('ops summary: numbers match the real code and files; unrun items stay not_run', async () => {
  const s = await summaryWith(null);
  assert.equal(s.decider.ruleCount, RULE_IDS.length);
  assert.deepEqual(s.decider.ruleIds, [...RULE_IDS]);
  assert.equal(s.decider.judgeVerdict.status, 'not_run');
  assert.equal(s.detection.events.status, 'not_run');
  assert.equal(s.revocation.status, 'not_run');
  assert.equal(s.recovery.noteRestoreRun.status, 'not_run');
  assert.equal(s.recovery.status, 'confirmed_now');
  assert.equal(s.recovery.backupRevision, 1);
  assert.equal(s.recovery.policyMatchesBackup, true);
  assert.equal(s.device.status, 'not_connected');
  assert.equal(s.device.approval, 'unavailable');
});

test('ops summary: a missing adapter never looks approved; an engine answer is shown as given', async () => {
  assert.equal((await summaryWith(null)).device.status, 'not_connected');
  const open = await summaryWith({ getApproval: async () => 'pending' });
  assert.deepEqual([open.device.status, open.device.approval], ['confirmed_now', 'pending']);
});

test('ops summary: a tampered or missing policy backup is reported, not hidden', () => {
  const inputs = loadInputs();
  const bad = buildOpsSummary({ ...inputs, backup: { ...inputs.backup, policyRevision: 9 }, device: null, now: NOW });
  assert.equal(bad.recovery.policyMatchesBackup, false);
  assert.equal(bad.recovery.reason, 'invalid_policy_backup');
  const none = buildOpsSummary({ ...inputs, backup: null, device: null, now: NOW });
  assert.deepEqual([none.recovery.status, none.recovery.reason], ['not_run', 'policy_backup_missing']);
});

test('ops summary: no note bodies, tokens, keys or confirmation codes leave the server', async () => {
  const text = JSON.stringify(await summaryWith(null));
  assert.ok(!/"(body|title|token|access_token|authorization|confirmation|secret|password)"/iu.test(text));
  assert.ok(!/sb_secret_|sb_publishable_|Bearer\s|eyJ[A-Za-z0-9_-]{12,}/u.test(text));
});

test('ops handler: GET only, no-store, load failure closes with 500', async () => {
  const handler = createOpsHandler({ service: createDeviceService({ now: () => NOW }), now: () => NOW });
  const ok = await call(handler, { method: 'GET' });
  assert.equal(ok.code, 200);
  assert.equal(ok.body.schema, 'vault.ops.summary.v1');
  assert.equal(ok.headers['Cache-Control'], 'no-store');
  assert.equal((await call(handler, { method: 'POST' })).code, 405);
  const broken = await call(createOpsHandler({ load: () => { throw new Error('x'); } }), { method: 'GET' });
  assert.equal(broken.code, 500);
});

test('ops screen model: labels come from server status only; broken or foreign summaries show nothing', async () => {
  const s = await summaryWith(null);
  const rows = summaryRows(s);
  assert.ok(rows.length >= 10);
  assert.equal(rows.find((r) => r.item === '규칙 수').value, String(RULE_IDS.length));
  assert.equal(rows.find((r) => r.item === '심판 판정 결과').label, '미실행');
  assert.equal(rows.find((r) => r.item === '승인 상태').label, '미연결');
  assert.equal(statusLabel('success'), '미확인');
  assert.equal(statusLabel(undefined), '미확인');
  assert.deepEqual(summaryRows(null), []);
  assert.deepEqual(summaryRows({ ...s, schema: 'x' }), []);
  const forged = summaryRows({ ...s, device: { status: 'passed', approval: 'approved' } });
  assert.equal(forged.find((r) => r.item === '승인 상태').label, '미확인');
});

test('ops screen cross-check: the summary must agree with a separate device-status response', async () => {
  const s = await summaryWith(null);
  const direct = await createDeviceService({ now: () => NOW }).status({}, null);
  assert.equal(crossCheck(s, direct).match, true);
  assert.equal(crossCheck(s, { ...direct, approval: 'approved' }).match, false);
  assert.equal(crossCheck(s, null).match, null);
  assert.equal(crossCheck(null, direct).match, null);
});

test('ops screen files: no browser storage, no key wording, loads the shared model', () => {
  const read = (name) => readFileSync(new URL(`../public/${name}`, import.meta.url), 'utf8');
  for (const name of ['ops.html', 'ops.js', 'ops-model.js']) {
    assert.ok(!/localStorage|sessionStorage|indexedDB|기기 ?키|device ?key|privateKey/iu.test(read(name)), name);
  }
  assert.match(read('ops.js'), /from '\.\/ops-model\.js'/u);
  assert.match(read('ops.html'), /\/ops\.js/u);
});