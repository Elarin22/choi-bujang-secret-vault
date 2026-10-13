import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { createNoticesHandler } from '../src/notices-api.mjs';

test('zone policy allows self-list reads, denies ambiguous lists and mutations lacking ownership evidence', async () => {
  const normal = fixtureRequests().normal, id = randomUUID();
  assert.equal((await decide({ ...normal, route: 'GET /api/my/notes', path: '/api/my/notes' })).decision, 'allow');
  assert.equal((await decide({ ...normal, route: 'GET /api/notes', path: '/api/notes' })).decision, 'deny');
  assert.equal((await decide({ ...normal, method: 'PUT', route: 'PUT /api/notes/:id', path: `/api/notes/${id}` })).decision, 'deny');
  for (const patch of [{ path: '/notes/export' }, { queryLength: 8 }, { service: 'notices' },
    { method: 'PUT', route: 'PUT /api/notes/:id', path: '/api/notes/export' }]) assert.equal((await decide({ ...normal, ...patch })).decision, 'deny');
});

test('notice edit requires server-owned instructor membership; caller roles never confer access', async () => {
  const teacher = randomUUID(), student = randomUUID(), id = randomUUID(); let updates = 0;
  const row = { id, title: 'Fictional notice', body: 'Practice only' };
  const clientFactory = () => ({ from() { const q = { select() { return q; }, eq() { return q; },
    update(value) { updates++; Object.assign(row, value); return q; }, async maybeSingle() { return { data: { ...row }, error: null }; } }; return q; } });
  const handler = createNoticesHandler({ env: { SUPABASE_URL: 'https://example.supabase.co', SUPABASE_SECRET_KEY: 'unit-test-only', INSTRUCTOR_USER_IDS: teacher },
    approvalVerifier: async () => true, clientFactory, verifierFactory: () => async auth => ({ userId: auth === 'Bearer Teacher' ? teacher : student }) });
  const call = async (auth, method, body) => { const res = { setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
    await handler({ method, query: { id }, headers: { authorization: auth }, body }, res); return res; };
  assert.equal((await call(undefined, 'GET')).code, 401);
  assert.equal((await call('Bearer Student', 'GET')).code, 200);
  assert.equal((await call('Bearer Student', 'PUT', { title: 'Bad', body: 'Bad', role: 'instructor' })).code, 403); assert.equal(updates, 0);
  assert.equal((await call('Bearer Teacher', 'PUT', { title: 'Good', body: 'Fictional' })).code, 200); assert.equal(updates, 1);
  assert.equal((await call('Bearer Teacher', 'PUT', { title: 'Bad', body: 'Bad', role: 'instructor' })).code, 400); assert.equal(updates, 1);
});
