import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'GET만 허용됩니다.' });
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) {
    return res.status(500).json({ error: '서버 설정이 완료되지 않았습니다.' });
  }
  const db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await db.from('notes').select('title, content').order('id', { ascending: true });
  if (error) {
    console.error('notes query failed', error.code ?? 'unknown');
    return res.status(500).json({ error: '자료를 읽지 못했습니다.' });
  }
  return res.status(200).json({ notes: data });
}
