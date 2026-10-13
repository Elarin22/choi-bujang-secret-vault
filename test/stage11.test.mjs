import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { connectionView, unavailableConnection } from '../src/connection-model.mjs';
import approvalHandler from '../api/device-approval.mjs';
import { randomUUID } from 'node:crypto';
import { createApprovedAccess } from '../src/approved-access.mjs';
import { createNotesHandler } from '../src/notes-api.mjs';
import { createNoticesHandler } from '../src/notices-api.mjs';
import { createRestoreHandler } from '../src/restore-api.mjs';

test('installed, caller-approved, stale or offline state cannot open protected data', () => {
  assert.equal(connectionView({ installed: true, approved: true }).canOpen, false);
  assert.equal(connectionView({ ...unavailableConnection('fixture', new Date().toISOString()), approval: 'approved' }).canOpen, false);
  const engineFixture = { schema: 'vault.connection.v1', authority: 'ALEPH SDP engine', connected: true, approval: 'approved', checkedAt: new Date().toISOString() };
  assert.equal(connectionView(engineFixture).canOpen, true);
  assert.equal(connectionView(engineFixture, false).canOpen, false);
  assert.equal(connectionView({ ...engineFixture, approval: 'pending' }).canOpen, false);
  assert.equal(connectionView({ ...engineFixture, checkedAt: new Date(Date.now() - 60000).toISOString() }).canOpen, false);
});

test('approval POST is an unavailable adapter result, never self-enrollment', () => {
  const res = { setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
  approvalHandler({ method: 'POST', body: { approved: true, role: 'operator', deviceRegistered: true } }, res);
  assert.equal(res.code, 503); assert.equal(res.body.connected, false); assert.equal(res.body.approval, 'unavailable');
});

test('offline caching is restricted to static UI, without API/data/session caching', async () => {
  const source = await readFile(new URL('../public/connect-sw.js', import.meta.url), 'utf8');
  const events = {}, handlers = [];
  const define = new Function('self', 'caches', 'fetch', `${source}; return PUBLIC_UI;`);
  const files = define({ location: { origin: 'https://fixture.local' }, addEventListener(name, handler) { events[name] = handler; } }, {}, () => {});
  assert.ok(files.every(path => !path.startsWith('/api/') && !['/vault.html', '/app.js', '/data.json'].includes(path)));
  for (const path of ['/api/notes', '/api/auth-config', '/vault.html', '/connect.html?token=untrusted']) {
    events.fetch({ request: { method: 'GET', url: `https://fixture.local${path}` }, respondWith() { handlers.push(path); } });
  }
  assert.deepEqual(handlers, []);
});

test('default entry is approval-only and the approved target retains the existing login workspace', async () => {
  const root = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const vault = await readFile(new URL('../public/vault.html', import.meta.url), 'utf8');
  assert.ok(root.includes('rel="manifest"')); assert.ok(root.includes('id="open-vault" disabled'));
  assert.ok(!root.includes('id="workspace"')); assert.ok(!root.includes('id="notes"')); assert.ok(!root.includes('id="login"'));
  assert.ok(vault.includes('id="workspace" hidden')); assert.ok(vault.includes('src="/app.js"'));
});

test('authenticated calls cannot bypass missing, denied or failed approval on any protected API', async () => {
  let storageCalls = 0;
  const user = { kind: 'student', userId: randomUUID() };
  const env = { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_SECRET_KEY: 'unit-test-only' };
  const response = () => ({ setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });
  for (const approvalVerifier of [undefined, async () => false, async () => 'true', async () => { throw new Error('unavailable'); }]) {
    const options = { env, approvalVerifier, verifierFactory: () => async () => user,
      clientFactory: () => { storageCalls++; throw new Error('must not access storage'); } };
    for (const handler of [createNotesHandler(options), createNotesHandler({ ...options, item: true }), createNoticesHandler(options), createRestoreHandler(options)]) {
      for (const method of ['GET', 'POST', 'PUT', 'DELETE']) {
        const res = response();
        await handler({ method, headers: { authorization: 'Bearer Fixture', 'x-device-approved': 'true' },
          query: { id: randomUUID(), noteId: randomUUID(), approved: 'true' }, body: { approved: true, deviceRegistered: true } }, res);
        assert.ok([403, 503].includes(res.code));
        assert.ok(['device_approval_required', 'device_verification_unavailable'].includes(res.body.error));
      }
    }
  }
  assert.equal(storageCalls, 0);
});

test('approval is reverified for every request and revocation stops formerly approved reads', async () => {
  let approved = true, checks = 0, reads = 0;
  const user = { userId: randomUUID() };
  const handler = createNotesHandler({ env: { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_SECRET_KEY: 'unit-test-only' },
    verifierFactory: () => async () => user, approvalVerifier: async (req, identity) => {
      checks++; assert.equal(identity, user); assert.equal(req.method, 'GET'); return approved;
    }, clientFactory: () => ({ from() { const q = { select() { return q; }, eq() { return q; },
      async order() { reads++; return { data: [], error: null }; } }; return q; } }) });
  const call = async () => { const res = { setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
    await handler({ method: 'GET', headers: { authorization: 'Bearer Fixture' } }, res); return res; };
  assert.equal((await call()).code, 200);
  approved = false; assert.equal((await call()).code, 403);
  assert.equal(checks, 2); assert.equal(reads, 1);
});

test('UI never requests notes before approval, and discards responses revoked while in flight', async () => {
  let approved = false, online = true, requests = 0, locks = 0;
  const state = () => ({ schema: 'vault.connection.v1', authority: 'ALEPH SDP engine', connected: true,
    approval: approved ? 'approved' : 'pending', checkedAt: new Date().toISOString() });
  const gate = createApprovedAccess({ readState: async () => state(), isOnline: () => online, onLock: () => locks++ });
  const read = async () => { requests++; return ['fictional data']; };
  assert.equal((await gate.run(read)).allowed, false); assert.equal(requests, 0);
  approved = true; assert.deepEqual(await gate.run(read), { allowed: true, value: ['fictional data'] });
  assert.deepEqual(await gate.run(async () => { requests++; approved = false; return ['must not paint']; }), { allowed: false });
  approved = true;
  assert.deepEqual(await gate.run(async () => { online = false; gate.invalidate(); return ['must not paint']; }), { allowed: false });
  assert.equal((await gate.run(read)).allowed, false); assert.equal(requests, 2); assert.ok(locks >= 4);
});
