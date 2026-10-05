import { randomUUID } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const COLUMNS = 'id, title, body';
const send = (res, code, body) => res.status(code).json(body);

function readBody(req) {
  try {
    const raw = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
  } catch { return null; }
}

function validFields(input, { requireTitle }) {
  const out = {};
  if (input.title !== undefined || requireTitle) {
    if (typeof input.title !== 'string' || !input.title.trim() || input.title.length > 200) return null;
    out.title = input.title;
  }
  if (input.body !== undefined) {
    if (typeof input.body !== 'string' || input.body.length > 5000) return null;
    out.body = input.body;
  }
  return out;
}

async function setup(req, res, getDeps, methods) {
  res.setHeader('Cache-Control', 'no-store');
  if (!methods.includes(req.method)) {
    res.setHeader('Allow', methods.join(', '));
    send(res, 405, { error: '허용되지 않는 요청 방식입니다.' });
    return null;
  }
  let deps;
  try { deps = getDeps(); } catch {
    send(res, 500, { error: '서버 설정이 완료되지 않았습니다.' });
    return null;
  }
  const who = await deps.verify(req.headers?.authorization);
  if (!who) {
    res.setHeader('WWW-Authenticate', 'Bearer');
    send(res, 401, { error: '로그인이 필요합니다.' });
    return null;
  }
  return { db: deps.db, userId: who.userId };
}

const fail = (res, error) => {
  console.error('notes query failed', error.code ?? 'unknown');
  return send(res, 500, { error: '자료를 처리하지 못했습니다.' });
};

export async function collection(req, res, getDeps) {
  const ctx = await setup(req, res, getDeps, ['GET', 'POST']);
  if (!ctx) return;
  if (req.method === 'GET') {
    const { data, error } = await ctx.db.from('notes').select(COLUMNS)
      .eq('owner_id', ctx.userId).order('created_at', { ascending: true });
    return error ? fail(res, error) : send(res, 200, data);
  }
  const input = readBody(req);
  const fields = input && validFields(input, { requireTitle: true });
  const id = input?.id ?? randomUUID();
  if (!fields || typeof id !== 'string' || !UUID.test(id)) {
    return send(res, 400, { error: '요청 형식이 맞지 않습니다.' });
  }
  const { error } = await ctx.db.from('notes')
    .insert({ id, owner_id: ctx.userId, title: fields.title, body: fields.body ?? '' });
  if (error?.code === '23505') return send(res, 409, { error: '이미 있는 id입니다.' });
  return error ? fail(res, error) : send(res, 201, { id });
}

export async function item(req, res, getDeps) {
  const ctx = await setup(req, res, getDeps, ['GET', 'PUT', 'DELETE']);
  if (!ctx) return;
  const id = req.query?.id;
  if (typeof id !== 'string' || !UUID.test(id)) return send(res, 404, { error: '없는 메모입니다.' });
  if (req.method === 'GET') {
    const { data, error } = await ctx.db.from('notes').select(COLUMNS).eq('id', id).maybeSingle();
    if (error) return fail(res, error);
    return data ? send(res, 200, data) : send(res, 404, { error: '없는 메모입니다.' });
  }
  if (req.method === 'PUT') {
    const input = readBody(req);
    const fields = input && validFields(input, { requireTitle: false });
    if (!fields || !Object.keys(fields).length) return send(res, 400, { error: '요청 형식이 맞지 않습니다.' });
    const { data, error } = await ctx.db.from('notes')
      .update({ ...fields, updated_at: new Date().toISOString() }).eq('id', id).select(COLUMNS);
    if (error) return fail(res, error);
    return data?.length ? send(res, 200, data[0]) : send(res, 404, { error: '없는 메모입니다.' });
  }
  const { data, error } = await ctx.db.from('notes').delete().eq('id', id).select('id');
  if (error) return fail(res, error);
  return data?.length ? send(res, 200, { id }) : send(res, 404, { error: '없는 메모입니다.' });
}
