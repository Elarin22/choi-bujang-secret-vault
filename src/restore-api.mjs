import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { requireApprovedRequest, verifyApprovedRequest } from './protected-access.mjs';
import { verifyPolicyBackup } from './policy-recovery.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
export const readPolicyBackup = () => JSON.parse(readFileSync(new URL('../backups/safe-policy.json', import.meta.url), 'utf8'));
const UUID = /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/iu;
export function createRestoreHandler({ env = process.env, clientFactory = createClient,
  verifierFactory = createLoginVerifier, policy = config, policyBackup, backupLoader = readPolicyBackup,
  approvalVerifier = verifyApprovedRequest } = {}) {
  let verify, db;
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    const auth = req.headers?.authorization;
    if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'authentication_required' });
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) return res.status(503).json({ error: 'storage_not_configured' });
    try {
      verify ??= verifierFactory({ config: policy, supabaseSecretKey: env.SUPABASE_SECRET_KEY });
      const user = await verify(auth);
      if (!user) return res.status(401).json({ error: 'invalid_authentication' });
      if (!await requireApprovedRequest(approvalVerifier, req, user, res)) return;
      if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
      const noteId = req.query?.noteId;
      if (typeof noteId !== 'string' || !UUID.test(noteId)) return res.status(400).json({ error: 'invalid_id' });
      if (req.body !== undefined && req.body !== null && req.body !== '' &&
        (typeof req.body !== 'object' || Array.isArray(req.body) || Object.keys(req.body).length !== 0)) {
        return res.status(400).json({ error: 'restore_body_not_allowed' });
      }
      // Reread and validate the prior copy immediately before any restore RPC.
      // A missing/corrupt copy aborts without invoking storage mutation.
      const safe = verifyPolicyBackup(policyBackup ?? backupLoader(), policy.repoUrl);
      if (JSON.stringify(policy.allowedRoutes.filter(route => route.service === 'notes')) !== JSON.stringify(safe.allowedRoutes)) {
        return res.status(503).json({ error: 'policy_restore_required' });
      }
      db ??= clientFactory(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, { auth: { persistSession: false, autoRefreshToken: false },
        global: { fetch: (url, options) => fetch(url, { ...options, signal: AbortSignal.timeout(8000) }) } });
      const result = await db.rpc('vault_restore_note', { target_note_id: noteId.toLowerCase(), verified_owner_id: user.userId });
      if (result.error) return res.status(result.error.code === 'P0002' ? 404 : 409).json({ error: 'restore_rejected' });
      if (!result.data || result.data.id !== noteId.toLowerCase() || result.data.verified !== true
        || !/^[a-f\d]{64}$/u.test(result.data.content_hash)) return res.status(502).json({ error: 'restore_verification_failed' });
      return res.status(200).json({ id: noteId.toLowerCase(), restored: true, verified: true });
    } catch { return res.status(503).json({ error: 'restore_unavailable' }); }
  };
}
