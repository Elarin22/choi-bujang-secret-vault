import { fail, send, readBody, setup, UUID, validFields } from './notes.mjs';
import { resourceId } from './resources.mjs';

const COLUMNS = 'id, title, body';

// 강사 권한은 저장된 staff_roles 표에서만 확인합니다. 화면 메뉴나 요청 본문의 role, 토큰의 이름표는 믿지 않습니다.
async function isInstructor(db, userId) {
  const { data, error } = await db.from('staff_roles').select('role').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return data?.role === 'instructor';
}

export async function noticeCollection(req, res, getDeps) {
  const ctx = await setup(req, res, getDeps, ['GET']);
  if (!ctx) return;
  res.setHeader('X-Resource-Kind', 'notice');
  const { data, error } = await ctx.db.from('notices').select(COLUMNS).order('created_at', { ascending: true });
  return error ? fail(res, error) : send(res, 200, data);
}

export async function noticeItem(req, res, getDeps) {
  const ctx = await setup(req, res, getDeps, ['GET', 'PUT']);
  if (!ctx) return;
  const id = req.query?.id;
  if (typeof id !== 'string' || !UUID.test(id)) return send(res, 404, { error: '없는 공지입니다.' });
  res.setHeader('X-Resource-Id', resourceId('notice', id));
  if (req.method === 'GET') {
    const { data, error } = await ctx.db.from('notices').select(COLUMNS).eq('id', id).maybeSingle();
    if (error) return fail(res, error);
    return data ? send(res, 200, data) : send(res, 404, { error: '없는 공지입니다.' });
  }
  let instructor;
  try { instructor = await isInstructor(ctx.db, ctx.userId); } catch (error) { return fail(res, error); }
  if (!instructor) return send(res, 403, { error: '공지는 강사만 고칠 수 있습니다.', reason: 'instructor_only' });
  const input = readBody(req);
  const fields = input && validFields(input, { requireTitle: false });
  if (!fields || !Object.keys(fields).length) return send(res, 400, { error: '요청 형식이 맞지 않습니다.' });
  const { data, error } = await ctx.db.from('notices')
    .update({ ...fields, updated_at: new Date().toISOString() }).eq('id', id).select(COLUMNS);
  if (error) return fail(res, error);
  return data?.length ? send(res, 200, data[0]) : send(res, 404, { error: '없는 공지입니다.' });
}
