import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { requireApprovedRequest, verifyApprovedRequest } from './protected-access.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const fields = 'id,title,body';
export function createNotesHandler({ item = false, env = process.env,
  clientFactory = createClient, verifierFactory = createLoginVerifier,
  approvalVerifier = verifyApprovedRequest } = {}) {
  let db, verify;
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const authorization = req.headers?.authorization;
    if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'authentication_required' });
    }
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) {
      return res.status(503).json({ error: 'storage_not_configured' });
    }
    try {
      if (!verify) verify = verifierFactory({ config, supabaseSecretKey: env.SUPABASE_SECRET_KEY });
      const user = await verify(authorization);
      if (!user) return res.status(401).json({ error: 'invalid_authentication' });
      if (!await requireApprovedRequest(approvalVerifier, req, user, res)) return;
      const methods = item ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
      if (!methods.includes(req.method)) {
        res.setHeader('Allow', methods.join(', '));
        return res.status(405).json({ error: 'method_not_allowed' });
      }
      const id = item ? req.query?.id : undefined;
      if (item && (typeof id !== 'string' || !UUID.test(id))) return res.status(400).json({ error: 'invalid_id' });
      if (!db) db = clientFactory(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
        global: { fetch: (url, options) => fetch(url, { ...options, signal: AbortSignal.timeout(8000) }) },
      });
      let result;
      if (req.method === 'GET') {
        const query = db.from('user_notes').select(fields);
        result = item ? await query.eq('id', id).eq('owner_id', user.userId).maybeSingle()
          : await query.eq('owner_id', user.userId).order('created_at');
      } else if (req.method === 'DELETE') {
        // Ownership is part of each SQL operation, avoiding a check/use race.
        result = await db.from('user_notes').delete().eq('id', id).eq('owner_id', user.userId).select('id').maybeSingle();
      } else {
        let body = req.body;
        if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = null; } }
        if (!body || typeof body !== 'object' || Array.isArray(body)
            || typeof body.title !== 'string' || !body.title.trim() || body.title.length > 200
            || typeof body.body !== 'string' || body.body.length > 10000
            || (req.method === 'POST' && body.id !== undefined && (typeof body.id !== 'string' || !UUID.test(body.id)))) {
          return res.status(400).json({ error: 'invalid_note' });
        }
        if (req.method === 'PUT' && Object.keys(body).some(key => !['title', 'body'].includes(key))) {
          return res.status(400).json({ error: 'invalid_note' });
        }
        const value = { title: body.title.trim(), body: body.body };
        result = req.method === 'POST'
          ? await db.from('user_notes').insert({ ...value, id: body.id ?? randomUUID(), owner_id: user.userId }).select(fields).single()
          : await db.from('user_notes').update(value).eq('id', id).eq('owner_id', user.userId).select(fields).maybeSingle();
      }
      if (result.error) return res.status(result.error.code === '23505' ? 409 : 502).json({ error: 'storage_unavailable' });
      if (item && !result.data) return res.status(404).json({ error: 'note_not_found' });
      return res.status(req.method === 'POST' ? 201 : 200).json(result.data);
    } catch {
      return res.status(502).json({ error: 'storage_unavailable' });
    }
  };
}
