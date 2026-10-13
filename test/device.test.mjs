import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createApprovalHandler, createDeviceService, createStatusHandler, requireApprovedRequest } from '../lib/device.mjs';
import { createApprovedAccess } from '../public/approved-access.js';
import { connectionView, unavailableConnection } from '../public/connection-model.js';

const NOW = new Date('2026-10-13T00:00:00.000Z');
const fresh = (approval, extra = {}) => ({ schema: 'vault.connection.v1', authority: 'ALEPH SDP engine', connected: true, approval, checkedAt: NOW.toISOString(), ...extra });
const call = async (handler, req) => {
  const out = { headers: {} };
  const res = { setHeader: (k, v) => { out.headers[k] = v; }, status: (c) => { out.code = c; return res; }, json: (b) => { out.body = b; return res; } };
  await handler({ headers: {}, ...req }, res);
  return out;
};

test('connectionView: only a fresh engine-confirmed approval opens; install, pending, denied, stale, forged or offline do not', () => {
  const now = NOW.getTime();
  assert.equal(connectionView(fresh('approved'), true, now).canOpen, true);
  assert.equal(connectionView(fresh('pending'), true, now).canOpen, false);
  assert.equal(connectionView(fresh('denied'), true, now).canOpen, false);
  assert.equal(connectionView(fresh('approved'), false, now).canOpen, false);
  assert.equal(connectionView(fresh('approved', { checkedAt: new Date(now - 31000).toISOString() }), true, now).canOpen, false);
  assert.equal(connectionView(fresh('approved', { authority: 'student_server' }), true, now).canOpen, false);
  assert.equal(connectionView(fresh('approved', { connected: false }), true, now).canOpen, false);
  assert.equal(connectionView(unavailableConnection('id', NOW.toISOString()), true, now).canOpen, false);
  assert.equal(connectionView(null, true, now).canOpen, false);
  assert.equal(connectionView({ ...fresh('approved'), schema: 'x' }, true, now).canOpen, false);
  assert.match(connectionView(null, true, now).detail, /설치 표시나 요청 버튼만으로/u);
});

test('device status: no official adapter keeps everything closed; no header, body or install mark grants approval', async () => {
  const handler = createStatusHandler({ service: createDeviceService({ now: () => NOW }) });
  const out = await call(handler, { method: 'GET', headers: { 'x-device-approved': 'true', 'x-approval': 'approved', cookie: 'approved=1' }, body: { approval: 'approved' } });
  assert.equal(out.code, 200);
  assert.equal(out.body.approval, 'unavailable');
  assert.equal(connectionView(out.body, true, NOW.getTime()).canOpen, false);
  assert.equal(out.headers['Cache-Control'], 'no-store');
  assert.equal((await call(handler, { method: 'POST' })).code, 405);
  const request = await call(createApprovalHandler({ service: createDeviceService({ now: () => NOW }) }), { method: 'POST' });
  assert.deepEqual([request.code, request.body.approval, request.body.error], [503, 'unavailable', 'official_adapter_not_provided']);
  assert.equal((await call(createApprovalHandler(), { method: 'GET' })).code, 405);
});

test('device status: adapter results are passed through; unknown values or adapter errors close', async () => {
  const make = (getApproval, requestApproval = async () => 'pending') => createDeviceService({ adapter: { getApproval, requestApproval }, now: () => NOW });
  for (const approval of ['approved', 'pending', 'denied']) {
    const out = await call(createStatusHandler({ service: make(async () => approval) }), { method: 'GET' });
    assert.equal(out.body.approval, approval);
    assert.equal(connectionView(out.body, true, NOW.getTime()).canOpen, approval === 'approved');
  }
  for (const bad of [async () => 'yes', async () => true, async () => { throw new Error('down'); }]) {
    assert.equal((await call(createStatusHandler({ service: make(bad) }), { method: 'GET' })).body.approval, 'unavailable');
  }
  const asked = await call(createApprovalHandler({ service: make(async () => 'denied') }), { method: 'POST' });
  assert.deepEqual([asked.code, asked.body.approval], [200, 'pending']);
});

test('server enforcement (REQUIRE_DEVICE_APPROVAL): off by default; on, only an approved device passes and a missing adapter fails closed', async () => {
  const res = () => { const o = {}; const r = { status: (c) => { o.code = c; return r; }, json: (b) => { o.body = b; return r; } }; return { r, o }; };
  const off = res();
  assert.equal(await requireApprovedRequest({}, { userId: 'u' }, off.r, { enforce: false }), true);
  const svc = (value) => createDeviceService({ adapter: { getApproval: async () => value } });
  const ok = res();
  assert.equal(await requireApprovedRequest({}, { userId: 'u' }, ok.r, { enforce: true, service: svc('approved') }), true);
  const no = res();
  assert.equal(await requireApprovedRequest({}, { userId: 'u' }, no.r, { enforce: true, service: svc('pending') }), false);
  assert.deepEqual([no.o.code, no.o.body.reason], [403, 'device_approval_required']);
  const none = res();
  assert.equal(await requireApprovedRequest({}, { userId: 'u' }, none.r, { enforce: true, service: createDeviceService() }), false);
  assert.deepEqual([none.o.code, none.o.body.reason], [503, 'device_verification_unavailable']);
});

test('approved access gate: no action before approval; a response is dropped when approval is revoked mid-flight', async () => {
  let approval = 'pending'; let locks = 0; let ran = 0;
  const gate = createApprovedAccess({ readState: async () => fresh(approval, { checkedAt: new Date().toISOString() }), isOnline: () => true, onLock: () => { locks += 1; } });
  assert.deepEqual(await gate.run(async () => { ran += 1; return 'notes'; }), { allowed: false });
  assert.equal(ran, 0);
  approval = 'approved';
  assert.deepEqual(await gate.run(async () => { ran += 1; return 'notes'; }), { allowed: true, value: 'notes' });
  const revoked = await gate.run(async () => { approval = 'denied'; return 'late notes'; });
  assert.deepEqual(revoked, { allowed: false });
  assert.ok(locks >= 2);
  const offline = createApprovedAccess({ readState: async () => fresh('approved', { checkedAt: new Date().toISOString() }), isOnline: () => false, onLock: () => {} });
  assert.deepEqual(await offline.run(async () => 'x'), { allowed: false });
});

test('installable app files: manifest, offline notice and a service worker that never caches API data', () => {
  const read = (name) => readFileSync(new URL(`../public/${name}`, import.meta.url), 'utf8');
  const manifest = JSON.parse(read('connect.webmanifest'));
  assert.ok(manifest.name && manifest.short_name && manifest.start_url === '/' && manifest.display === 'standalone');
  assert.ok(manifest.icons.length >= 1);
  const sw = read('connect-sw.js');
  assert.match(sw, /startsWith\('\/api\/'\)/u);
  assert.ok(!/authorization|token|private/iu.test(sw.replace(/토큰/gu, '')));
  for (const page of ['index.html', 'connect.html']) {
    const html = read(page);
    assert.match(html, /rel="manifest" href="\/connect\.webmanifest"/u);
    assert.ok(!/localStorage|sessionStorage|indexedDB/u.test(html));
    assert.ok(!/기기 ?키|device ?key|privateKey/iu.test(html));
  }
  assert.match(read('connect.html'), /설치했다는 표시만으로 기기가 확인된 것은 아닙니다/u);
  assert.match(read('connect.html'), /오프라인/u);
  assert.match(read('index.html'), /persistSession:\s*false/u);
  assert.ok(!/기기 ?키|device ?key|privateKey/iu.test(sw + read('connect.webmanifest') + read('connect.js')));
  // the vault page asks the server for approval before it even fetches the login settings
  const index = read('index.html');
  assert.ok(index.indexOf('/api/device-status') > -1 && index.indexOf('/api/device-status') < index.indexOf("fetch('/api/config'"));
});