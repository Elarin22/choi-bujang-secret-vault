// 10단계: 침해 전에 검증해 둔 안전 정책 사본(backups/safe-policy.json)과 현재 시험 정책의 차이를 보여 주고 되돌립니다.
// 순수 함수만 있습니다. 파일을 읽고 쓰는 일은 scripts/policy-restore.mjs가 하고, 실제 운영 정책은 건드리지 않습니다.
import { createHash } from 'node:crypto';

export const BACKUP_SCHEMA = 'vault.policy.backup.v1';
// 사본의 SHA-256 지문입니다. 사본이 바뀌었거나 깨졌으면 지문이 달라져 복원을 중단합니다.
export const SAFE_POLICY_HASH = '76c3a68d800d8dea061bbdab53d5a4d76477074efa49babd240dbae5b1dfd73a';
const hash = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
// 이 사본이 책임지는 서비스는 메모(notes)입니다. 공지(notices) 등 다른 서비스 규칙은 복원 때 그대로 둡니다.
export const isNotesRoute = (route) => typeof route === 'string' && /^[A-Z]+ \/api\/(?:my\/)?notes(?:\/|$)/u.test(route);

export function verifyPolicyBackup(backup, projectId) {
  if (!backup || typeof backup !== 'object' || backup.schema !== BACKUP_SCHEMA || backup.projectId !== projectId
    || backup.service !== 'notes' || backup.policyRevision !== 1 || !Array.isArray(backup.allowedRoutes)
    || !backup.allowedRoutes.every(isNotesRoute) || hash(backup) !== SAFE_POLICY_HASH) {
    throw new Error('invalid_policy_backup');
  }
  return structuredClone(backup);
}

function validState(state) {
  if (!state || typeof state.projectId !== 'string' || !Number.isSafeInteger(state.policyRevision)
    || !Array.isArray(state.allowedRoutes) || !state.allowedRoutes.every((route) => typeof route === 'string')
    || !Array.isArray(state.audit)) throw new Error('invalid_policy_state');
}

// 실행 전 미리보기: 복원할 사본 버전과 바뀔 항목만 계산합니다. 아무것도 쓰지 않습니다.
export function planPolicyRestore(state, backup) {
  const safe = verifyPolicyBackup(backup, state?.projectId);
  validState(state);
  const before = state.allowedRoutes.filter(isNotesRoute);
  const after = [...safe.allowedRoutes];
  const plan = {
    projectId: state.projectId, expectedRevision: state.policyRevision, service: 'notes', backupRevision: safe.policyRevision,
    before, after,
    added: after.filter((route) => !before.includes(route)),
    removed: before.filter((route) => !after.includes(route)),
    preservedOtherRoutes: state.allowedRoutes.filter((route) => !isNotesRoute(route)),
    preservedAuditEntries: state.audit.length,
  };
  plan.unchanged = !plan.added.length && !plan.removed.length;
  return { ...plan, confirmation: hash({ ...plan, preservedAuditEntries: undefined }) };
}

// 실행: 미리보기에서 보여 준 확인 코드를 그대로 받아야 합니다. 다른 서비스 규칙과 감사 기록은 지우지 않고 한 줄을 더합니다.
export function applyPolicyRestore(state, backup, confirmation) {
  const plan = planPolicyRestore(state, backup);
  if (confirmation !== plan.confirmation) throw new Error('restore_confirmation_required');
  return {
    ...structuredClone(state), policyRevision: state.policyRevision + 1,
    allowedRoutes: [...plan.after, ...plan.preservedOtherRoutes],
    audit: [...structuredClone(state.audit), { kind: 'policy_restore', revision: state.policyRevision + 1, backupRevision: plan.backupRevision }],
  };
}
