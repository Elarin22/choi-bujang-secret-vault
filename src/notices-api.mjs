import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { requireApprovedRequest, verifyApprovedRequest } from './protected-access.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const UUID = /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/iu;
// This separate resource never trusts a role/user supplied in a request.
// The server-owned instructor allowlist is empty until explicitly configured.
export function createNoticesHandler({ env = process.env, clientFactory = createClient,
  verifierFactory = createLoginVerifier, approvalVerifier = verifyApprovedRequest } = {}) {
  let verify, db;
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    const auth = req.headers?.authorization;
    if (typeof auth !== 'string' || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'authentication_required' });
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) return res.status(503).json({ error: 'storage_not_configured' });
    try {
      verify ??= verifierFactory({ config, supabaseSecretKey: env.SUPABASE_SECRET_KEY });
      const user = await verify(auth);
      if (!user) return res.status(401).json({ error: 'invalid_authentication' });
      if (!await requireApprovedRequest(approvalVerifier, req, user, res)) return;
      if (!['GET', 'PUT'].includes(req.method)) return res.status(405).json({ error: 'method_not_allowed' });
      const instructors = (env.INSTRUCTOR_USER_IDS ?? '').split(',').map(value => value.trim()).filter(value => UUID.test(value));
      if (req.method === 'PUT' && !instructors.includes(user.userId)) return res.status(403).json({ error: 'instructor_required' });
      const id = req.query?.id;
      if (typeof id !== 'string' || !UUID.test(id)) return res.status(400).json({ error: 'invalid_id' });
      let body = req.body;
      if (req.method === 'PUT') {
        if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = null; } }
        if (!body || Array.isArray(body) || Object.keys(body).sort().join(',') !== 'body,title'
          || typeof body.title !== 'string' || !body.title.trim() || body.title.length > 200
          || typeof body.body !== 'string' || body.body.length > 10000) return res.status(400).json({ error: 'invalid_notice' });
      }
      db ??= clientFactory(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, { auth: { persistSession: false, autoRefreshToken: false },
        global: { fetch: (url, options) => fetch(url, { ...options, signal: AbortSignal.timeout(8000) }) } });
      const q = req.method === 'GET' ? db.from('vault_notices').select('id,title,body')
        : db.from('vault_notices').update({ title: body.title.trim(), body: body.body }).select('id,title,body');
      const result = await q.eq('id', id).maybeSingle();
      if (result.error) return res.status(503).json({ error: 'notice_storage_unavailable' });
      if (!result.data) return res.status(404).json({ error: 'notice_not_found' });
      return res.status(200).json(result.data);
    } catch { return res.status(503).json({ error: 'notice_storage_unavailable' }); }
  };
}
