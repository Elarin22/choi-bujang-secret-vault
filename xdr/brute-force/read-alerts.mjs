import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

export const MASK = '[가림]';
const SECRET_LIKE = [
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization)\b\s*[=:]\s*\S+/giu,
  /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/giu,
  /\bsb_(?:secret|publishable)_[A-Za-z0-9_-]+/gu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/gu,
  /\b[A-Fa-f0-9]{32,}\b/gu,
  /[A-Za-z0-9+/_-]{40,}={0,2}/gu,
];

export function redact(text) {
  return SECRET_LIKE.reduce((out, pattern) => out.replace(pattern, MASK), String(text));
}

function toIso(timestamp) {
  if (typeof timestamp !== 'string') return null;
  const fixed = timestamp.replace(/([+-]\d{2})(\d{2})$/u, '$1:$2');
  const ms = Date.parse(fixed);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

// Pick only the fields the detector needs. The original alert object is never changed or returned.
export function extract(alert, index) {
  const a = alert && typeof alert === 'object' ? alert : {};
  const data = a.data && typeof a.data === 'object' ? a.data : {};
  const ip = data.srcip ?? data.src_ip;
  const account = data.dstuser ?? data.srcuser ?? data.user;
  const level = Number(a.rule?.level);
  return Object.freeze({
    alertId: typeof a.id === 'string' && a.id ? a.id : `row-${index + 1}`,
    at: toIso(a.timestamp),
    srcip: typeof ip === 'string' && isIP(ip) ? ip : null,
    account: typeof account === 'string' && account ? redact(account.slice(0, 64)) : null,
    level: Number.isFinite(level) ? level : null,
    description: typeof a.rule?.description === 'string' ? redact(a.rule.description.slice(0, 300)) : '',
  });
}

export async function readAlerts(path) {
  const text = await readFile(path, 'utf8');
  let list;
  try {
    const parsed = JSON.parse(text);
    list = Array.isArray(parsed) ? parsed : parsed?.alerts;
  } catch {
    list = text.split(/\r?\n/u).filter((line) => line.trim()).map((line) => JSON.parse(line));
  }
  if (!Array.isArray(list)) throw new Error('Wazuh 경보 배열을 찾지 못했습니다.');
  return list.map(extract);
}
