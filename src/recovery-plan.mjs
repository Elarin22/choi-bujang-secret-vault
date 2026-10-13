import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { planPolicyRestore, SAFE_POLICY_HASH } from './policy-recovery.mjs';
const readConfig = () => JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const readBackup = () => JSON.parse(readFileSync(new URL('../backups/safe-policy.json', import.meta.url), 'utf8'));
// Only public policy metadata. Never returns memo copies, tokens, owners or audit rows.
export function createRecoveryPlanHandler({ configLoader = readConfig, backupLoader = readBackup } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    const requestId = randomUUID(), checkedAt = new Date().toISOString();
    if (req.method !== 'GET') return res.status(405).json({ error: 'method_not_allowed', requestId, checkedAt });
    try {
      const config = configLoader(), backup = backupLoader();
      const plan = planPolicyRestore({ projectId: config.repoUrl, policyRevision: backup.policyRevision,
        allowedRoutes: config.allowedRoutes, audit: [] }, backup);
      return res.status(200).json({ schema: 'vault.recovery.plan.v1', requestId, checkedAt,
        backupVerified: true, backupRevision: plan.backupRevision, backupHash: SAFE_POLICY_HASH,
        scope: plan.service, changes: { before: plan.before, after: plan.after },
        confirmation: plan.confirmation, operationalPolicyWrite: false });
    } catch { return res.status(409).json({ error: 'backup_verification_failed', backupVerified: false, requestId, checkedAt }); }
  };
}
