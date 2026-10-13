import { readFileSync } from 'node:fs';
import { collectOperationsStatus } from '../src/operations-status.mjs';
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') return res.status(405).json({ error: 'method_not_allowed' });
  try {
    const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
    const matrix = JSON.parse(readFileSync(new URL('../data/attack-matrix.json', import.meta.url), 'utf8'));
    return res.status(200).json(await collectOperationsStatus(config, matrix, { commit: process.env.VERCEL_GIT_COMMIT_SHA }));
  } catch { return res.status(503).json({ error: 'observation_unavailable' }); }
}
