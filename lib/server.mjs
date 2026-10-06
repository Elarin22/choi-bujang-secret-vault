import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

let cached;

export function loadConfig() {
  return JSON.parse(readFileSync(join(process.cwd(), 'aleph.config.json'), 'utf8'));
}

export function getDeps() {
  if (cached) return cached;
  const config = loadConfig();
  const issuer = config.identityProvider?.issuer ?? '';
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (issuer.includes('REPLACE') || !url || !key) throw new Error('config_not_ready');
  cached = {
    verify: createLoginVerifier({ config, supabaseSecretKey: key }),
    db: createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } }),
  };
  return cached;
}
