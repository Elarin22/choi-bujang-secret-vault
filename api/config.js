import { loadConfig } from '../lib/server.mjs';

export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const key = process.env.SUPABASE_PUBLISHABLE_KEY;
  let origin = null;
  try { origin = new URL(loadConfig().identityProvider?.issuer).origin; } catch { /* handled below */ }
  if (req.method !== 'GET' || !origin || origin.includes('REPLACE')
      || typeof key !== 'string' || !key.startsWith('sb_publishable_')) {
    return res.status(500).json({ error: '로그인 설정이 완료되지 않았습니다.' });
  }
  return res.status(200).json({ supabaseUrl: origin, publishableKey: key });
}
