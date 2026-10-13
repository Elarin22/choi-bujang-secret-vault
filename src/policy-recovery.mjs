import { createHash } from 'node:crypto';
export const SAFE_POLICY_HASH = '83b2809b4380d07ac808cb7600da746da7b1a73495f13d2b287367830187c752';
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
export function verifyPolicyBackup(backup, projectId) {
  if (!backup || backup.schema !== 'vault.policy.backup.v1' || backup.projectId !== projectId
    || backup.service !== 'notes' || backup.policyRevision !== 1 || hash(backup) !== SAFE_POLICY_HASH) {
    throw new Error('invalid_policy_backup');
  }
  return structuredClone(backup);
}
export function planPolicyRestore(state, backup) {
  const safe = verifyPolicyBackup(backup, state.projectId);
  if (!Number.isSafeInteger(state.policyRevision) || !Array.isArray(state.allowedRoutes) || !Array.isArray(state.audit)) throw new Error('invalid_policy_state');
  const previous = state.allowedRoutes.filter(route => route.service === 'notes');
  const plan = { projectId: state.projectId, expectedRevision: state.policyRevision, service: 'notes',
    backupRevision: safe.policyRevision, before: structuredClone(previous), after: safe.allowedRoutes };
  return { ...plan, confirmation: hash(plan) };
}
export function applyPolicyRestore(state, backup, confirmation) {
  const plan = planPolicyRestore(state, backup);
  if (confirmation !== plan.confirmation) throw new Error('restore_confirmation_required');
  return { ...structuredClone(state), policyRevision: state.policyRevision + 1,
    allowedRoutes: [...state.allowedRoutes.filter(route => route.service !== 'notes'), ...plan.after],
    audit: [...structuredClone(state.audit), { kind: 'policy_restore', revision: state.policyRevision + 1, backupRevision: plan.backupRevision }] };
}
