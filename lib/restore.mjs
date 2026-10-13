import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { send, setup, UUID } from './notes.mjs';
import { isNotesRoute, verifyPolicyBackup } from '../src/policy-recovery.mjs';
import { resourceId } from './resources.mjs';

const readConfig = () => JSON.parse(readFileSync(join(process.cwd(), 'aleph.config.json'), 'utf8'));
export const readPolicyBackup = () => JSON.parse(readFileSync(join(process.cwd(), 'backups', 'safe-policy.json'), 'utf8'));

// POST /api/restore/:noteId — 검증된 사용자 본인의 비공개 사본 한 건만 되살립니다.
// 본문·쿼리·요청의 owner/role은 보지 않고, 소유자는 로그인 검증 결과로만 정합니다.
export async function restore(req, res, getDeps, { loadBackup = readPolicyBackup, loadPolicy = readConfig } = {}) {
  const ctx = await setup(req, res, getDeps, ['POST']);
  if (!ctx) return;
  const noteId = req.query?.noteId;
  if (typeof noteId !== 'string' || !UUID.test(noteId)) return send(res, 400, { error: '요청 형식이 맞지 않습니다.' });
  const body = req.body;
  if (body !== undefined && body !== null && body !== '' && (typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length)) {
    return send(res, 400, { error: '복원 요청에는 본문을 넣을 수 없습니다.' });
  }
  const id = noteId.toLowerCase();
  res.setHeader('X-Resource-Id', resourceId('note', id));
  // 복원 직전에 정책 사본을 다시 읽어 검증합니다. 사본이 없거나 깨졌거나 현재 메모 정책이 사본과 다르면 저장소는 건드리지 않습니다.
  let policy;
  try {
    policy = loadPolicy();
    const safe = verifyPolicyBackup(loadBackup(), policy.repoUrl);
    const current = (policy.allowedRoutes ?? []).filter(isNotesRoute);
    if (JSON.stringify(current) !== JSON.stringify(safe.allowedRoutes)) {
      return send(res, 503, { error: '안전 정책을 먼저 되돌려야 합니다.', reason: 'policy_restore_required' });
    }
  } catch {
    return send(res, 503, { error: '안전 정책 사본을 확인하지 못해 중단했습니다.', reason: 'invalid_policy_backup' });
  }
  const result = await ctx.db.rpc('restore_note', { target_note_id: id, verified_owner_id: ctx.userId });
  if (result.error) {
    return result.error.code === 'P0002'
      ? send(res, 404, { error: '복원할 내 사본이 없습니다.', reason: 'backup_not_found' })
      : send(res, 409, { error: '복원이 거부되었습니다.', reason: 'restore_rejected' });
  }
  const data = result.data;
  if (!data || data.id !== id || data.verified !== true || !/^[a-f\d]{64}$/u.test(String(data.content_hash))) {
    return send(res, 502, { error: '복원 결과를 확인하지 못했습니다.', reason: 'restore_verification_failed' });
  }
  return send(res, 200, { id, restored: true, verified: true });
}
