import assert from 'node:assert/strict';
import { test } from 'node:test';
import { collection, item } from '../lib/notes.mjs';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';

function fakeDb() {
  const rows = [];
  const pick = (r, cols) => Object.fromEntries(cols.split(',').map((c) => c.trim()).map((c) => [c, r[c]]));
  const query = (op, payload, cols = 'id, title, body') => {
    const filters = [];
    const q = {
      select: (c) => { if (c) cols = c; return q; }, eq: (k, v) => { filters.push([k, v]); return q; }, order: () => q,
      maybeSingle: async () => { const r = match()[0]; return { data: r ? pick(r, cols) : null, error: null }; },
      then: (resolve) => resolve(run()),
    };
    const match = () => rows.filter((r) => filters.every(([k, v]) => r[k] === v));
    const run = () => {
      if (op === 'select') return { data: match().map((r) => pick(r, cols)), error: null };
      if (op === 'insert') {
        if (rows.some((r) => r.id === payload.id)) return { data: null, error: { code: '23505' } };
        rows.push({ ...payload }); return { data: null, error: null };
      }
      if (op === 'update') { const m = match(); m.forEach((r) => Object.assign(r, payload)); return { data: m.map((r) => pick(r, cols)), error: null }; }
      const m = match(); m.forEach((r) => rows.splice(rows.indexOf(r), 1)); return { data: m.map(({ id }) => ({ id })), error: null };
    };
    return q;
  };
  return { from: () => ({ select: (c) => query('select', undefined, c), insert: (p) => query('insert', p),
    update: (p) => query('update', p), delete: () => query('delete') }) };
}

const call = async (fn, req, deps) => {
  const out = { headers: {} };
  const res = { setHeader: (k, v) => { out.headers[k] = v; }, status: (c) => { out.code = c; return res; }, json: (b) => { out.body = b; return res; } };
  await fn({ headers: {}, query: {}, ...req }, res, () => { if (!deps) throw new Error('config_not_ready'); return deps; });
  return out;
};

test('notes CRUD requires verified login and uses server user id', async () => {
  const db = fakeDb();
  const verify = async (h) => (h === 'Bearer a' ? { userId: A } : h === 'Bearer b' ? { userId: B } : null);
  const deps = { db, verify };
  const auth = (t) => ({ authorization: `Bearer ${t}` });

  assert.equal((await call(collection, { method: 'GET' }, deps)).code, 401);
  assert.equal((await call(collection, { method: 'POST', body: { title: 'x' } }, deps)).code, 401);
  assert.equal((await call(collection, { method: 'PATCH', headers: auth('a') }, deps)).code, 405);

  const made = await call(collection, { method: 'POST', headers: auth('a'), body: { title: 't1', body: 'b1', userId: B, owner_id: B } }, deps);
  assert.equal(made.code, 201);
  const id = made.body.id;
  assert.match(id, /^[0-9a-f-]{36}$/u);
  assert.equal((await call(collection, { method: 'POST', headers: auth('a'), body: { id, title: 'dup' } }, deps)).code, 409);
  assert.equal((await call(collection, { method: 'POST', headers: auth('a'), body: { title: '' } }, deps)).code, 400);

  const list = await call(collection, { method: 'GET', headers: auth('a') }, deps);
  assert.deepEqual(list.body, [{ id, title: 't1', body: 'b1' }]);
  assert.deepEqual((await call(collection, { method: 'GET', headers: auth('b') }, deps)).body, []);

  assert.deepEqual((await call(item, { method: 'GET', headers: auth('a'), query: { id } }, deps)).body, { id, title: 't1', body: 'b1' });
  assert.equal((await call(item, { method: 'GET', query: { id } }, deps)).code, 401);
  const put = await call(item, { method: 'PUT', headers: auth('a'), query: { id }, body: { title: 't2', body: 'b2' } }, deps);
  assert.deepEqual(put.body, { id, title: 't2', body: 'b2' });
  assert.equal((await call(item, { method: 'DELETE', headers: auth('a'), query: { id } }, deps)).code, 200);
  assert.equal((await call(item, { method: 'GET', headers: auth('a'), query: { id } }, deps)).code, 404);
  assert.equal((await call(item, { method: 'GET', headers: auth('a'), query: { id: 'not-a-uuid' } }, deps)).code, 404);
});

test('fails closed when server config is missing', async () => {
  const out = await call(collection, { method: 'GET', headers: { authorization: 'Bearer a' } }, null);
  assert.equal(out.code, 500);
});

test('A and B can only touch their own notes and cannot change owners', async () => {
  const db = fakeDb();
  const verify = async (h) => (h === 'Bearer a' ? { userId: A } : h === 'Bearer b' ? { userId: B } : null);
  const deps = { db, verify };
  const auth = (t) => ({ authorization: `Bearer ${t}` });

  // body owner_id is ignored on create: the verified user becomes the owner
  const made = await call(collection, { method: 'POST', headers: auth('a'), body: { title: 'a1', body: 'secret', owner_id: B } }, deps);
  const id = made.body.id;
  const own = await call(collection, { method: 'POST', headers: auth('b'), body: { title: 'b1', body: 'mine' } }, deps);
  assert.equal(own.code, 201);

  assert.equal((await call(collection, { method: 'GET', headers: auth('a') }, deps)).body.length, 1);
  const listB = (await call(collection, { method: 'GET', headers: auth('b') }, deps)).body;
  assert.deepEqual(listB.map((n) => n.title), ['b1']);

  for (const method of ['GET', 'PUT', 'DELETE']) {
    const r = await call(item, { method, headers: auth('b'), query: { id }, body: { title: 'hacked' } }, deps);
    assert.equal(r.code, 403, method);
    assert.equal(JSON.stringify(r.body).includes('secret'), false);
  }
  // owner change attempts are refused, own fields still update
  assert.equal((await call(item, { method: 'PUT', headers: auth('a'), query: { id }, body: { title: 'x', owner_id: B } }, deps)).code, 403);
  const ok = await call(item, { method: 'PUT', headers: auth('a'), query: { id }, body: { title: 'a2', owner_id: A } }, deps);
  assert.deepEqual(ok.body, { id, title: 'a2', body: 'secret' });
  assert.deepEqual((await call(item, { method: 'GET', headers: auth('a'), query: { id } }, deps)).body, { id, title: 'a2', body: 'secret' });
  assert.equal((await call(item, { method: 'GET', headers: auth('b'), query: { id: '33333333-3333-4333-8333-333333333333' } }, deps)).code, 404);
  assert.equal((await call(item, { method: 'DELETE', headers: auth('a'), query: { id } }, deps)).code, 200);
});
