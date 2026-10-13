import { randomUUID } from 'node:crypto';
import { unavailableConnection } from '../src/connection-model.mjs';
export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') return res.status(405).json({ error: 'method_not_allowed' });
  return res.status(200).json(unavailableConnection(randomUUID(), new Date().toISOString()));
}
