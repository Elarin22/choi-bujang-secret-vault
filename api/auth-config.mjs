export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') return res.status(405).json({ error: 'method_not_allowed' });
  const { SUPABASE_URL: url, SUPABASE_PUBLISHABLE_KEY: publishableKey } = process.env;
  if (!url || !/^sb_publishable_[A-Za-z0-9_-]+$/u.test(publishableKey ?? '')) {
    return res.status(503).json({ error: 'login_not_configured' });
  }
  // Explicit public allowlist: never serialize process.env or the server key.
  return res.status(200).json({ url, publishableKey });
}
