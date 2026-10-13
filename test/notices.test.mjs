import assert from 'node:assert/strict';
import { test } from 'node:test';
import { noticeCollection, noticeItem } from '../lib/notices.mjs';
import { collection, item } from '../lib/notes.mjs';
import { parseResourceId, resourceId } from '../lib/resources.mjs';

const A = '11111111-1111-4111-8111-111111111111';
const TEACHER = '99999999-9999-4999-8999-999999999999';
const NID = '33333333-3333-4333-8333-333333333333';
const NOTE = '44444444-4444-4444-8444-444444444444';

function fakeDb() {
  const tables = {
    notices: [{ id: NID, title: '공지', body: '내용', created_at: 1 }],
    staff_roles: [{ user_id: TEACHER, role: 'instructor' }],
    notes: [{ id: NOTE, owner_id: A, title: 'a', body: 'secret' }],
  };
  const from = (name) => {
    const filters = [];
    let patch = null;
    const rows = () => tables[name].filter((r) => filters.every(([k, v]) => r[k] === v));
    const q = {
      select: () => q, order: () => q, eq: (k, v) => { filters.push([k, v]); return q; },
      update: (p) => { patch = p; return q; },
      maybeSingle: async () => ({ data: rows()[0] ? { ...rows()[0] } : null, error: null }),
      then: (resolve) => {
        const hit = rows();
        if (patch) hit.forEach((r) => Object.assign(r, patch));
        resolve({ data: hit.map(({ id, title, body }) => ({ id, title, body })), error: null });
      },
    };
    return q;
  };
  return { from, tables };
}

const call = async (fn, req, deps) => {
  const out = { headers: {} };
  const res = { setHeader: (k, v) => { out.headers[k] = v; }, status: (c) => { out.code = c; return res; }, json: (b) => { out.body = b; return res; } };
  await fn({ headers: {}, query: {}, ...req }, res, () => deps);
  return out;
};

test('notices: everyone logged in can read, only the stored instructor can edit, role in the body is ignored', async () => {
  const db = fakeDb();
  const verify = async (h) => ({ 'Bearer a': { userId: A }, 'Bearer t': { userId: TEACHER } })[h] ?? null;
  const deps = { db, verify };
  const auth = (t) => ({ authorization: `Bearer ${t}` });

  assert.equal((await call(noticeCollection, { method: 'GET' }, deps)).code, 401);
  assert.equal((await call(noticeItem, { method: 'PUT', query: { id: NID }, body: { title: 'x' } }, deps)).code, 401);
  const list = await call(noticeCollection, { method: 'GET', headers: auth('a') }, deps);
  assert.equal(list.code, 200);
  assert.equal(list.headers['X-Resource-Kind'], 'notice');
  assert.equal((await call(noticeItem, { method: 'GET', headers: auth('a'), query: { id: NID } }, deps)).body.title, '공지');

  const student = await call(noticeItem, { method: 'PUT', headers: auth('a'), query: { id: NID },
    body: { title: 'hacked', role: 'instructor', isInstructor: true } }, deps);
  assert.equal(student.code, 403);
  assert.equal(student.body.reason, 'instructor_only');
  assert.equal(db.tables.notices[0].title, '공지');

  const teacher = await call(noticeItem, { method: 'PUT', headers: auth('t'), query: { id: NID }, body: { title: '새 공지' } }, deps);
  assert.deepEqual(teacher.body, { id: NID, title: '새 공지', body: '내용' });
  assert.equal(teacher.headers['X-Resource-Id'], `notice:${NID}`);
  assert.equal((await call(noticeItem, { method: 'DELETE', headers: auth('t'), query: { id: NID } }, deps)).code, 405);
  assert.equal((await call(noticeItem, { method: 'GET', headers: auth('a'), query: { id: 'x' } }, deps)).code, 404);
});

test('notes API still refuses other users with a short reason and tags the resource kind', async () => {
  const db = fakeDb();
  const verify = async (h) => ({ 'Bearer a': { userId: A }, 'Bearer t': { userId: TEACHER } })[h] ?? null;
  const deps = { db, verify };
  const other = await call(item, { method: 'GET', headers: { authorization: 'Bearer t' }, query: { id: NOTE } }, deps);
  assert.equal(other.code, 403);
  assert.equal(other.body.reason, 'not_owner');
  assert.equal(JSON.stringify(other.body).includes('secret'), false);
  assert.equal(other.headers['X-Resource-Id'], `note:${NOTE}`);
  const mine = await call(item, { method: 'GET', headers: { authorization: 'Bearer a' }, query: { id: NOTE } }, deps);
  assert.deepEqual(mine.body, { id: NOTE, title: 'a', body: 'secret' });
  assert.equal((await call(collection, { method: 'GET', headers: { authorization: 'Bearer a' } }, deps)).headers['X-Resource-Kind'], 'note');
});

test('resource ids separate notes from notices', () => {
  assert.equal(resourceId('note', NOTE), `note:${NOTE}`);
  assert.deepEqual(parseResourceId(`notice:${NID}`), { kind: 'notice', id: NID });
  assert.equal(parseResourceId('other:1'), null);
  assert.throws(() => resourceId('role', 'x'));
});
