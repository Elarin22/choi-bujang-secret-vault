import { randomUUID } from 'node:crypto';
import { unavailableConnection } from '../src/connection-model.mjs';
export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  // No invented enrollment API, credential, certificate or browser permission.
  return res.status(503).json({ ...unavailableConnection(randomUUID(), new Date().toISOString()), error: 'official_adapter_not_provided' });
}
