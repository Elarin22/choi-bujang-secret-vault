import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export function redact(value) {
  return String(value ?? '').slice(0, 2000)
    .replace(/-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[\s\S]*?PRIVATE KEY-----/gu, '[redacted]')
    .replace(/\b(?:sb_secret_|sk-)[A-Za-z0-9_-]+|\bBearer\s+\S+|\beyJ[\w-]+\.[\w-]+\.[\w-]+/giu, '[redacted]')
    .replace(/\b(?:password|passwd|token|api[_-]?key|secret)\s*[:=]\s*[^\s,;]+/giu, '[redacted]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu, '[redacted]')
    .replace(/[\r\n\t]+/gu, ' ');
}
const pseudonym = value => `account-${createHash('sha256').update(String(value)).digest('hex').slice(0, 12)}`;
export function projectAlert(alert) {
  const time = Date.parse(alert?.timestamp);
  const account = alert?.data?.srcuser ?? alert?.data?.dstuser ?? null;
  return {
    timestamp: Number.isFinite(time) ? new Date(time).toISOString() : null,
    sourceIp: isIP(String(alert?.data?.srcip ?? '')) ? alert.data.srcip : null,
    account: account === null ? null : /^user\d{1,3}$/u.test(account) ? account : pseudonym(account),
    level: Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0,
    description: redact(alert?.rule?.description),
  };
}
export async function readFixture(path, moduleKey) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== moduleKey || !Array.isArray(fixture.alerts)) {
    throw new Error('XDR 시험 경보 형식을 확인하세요.');
  }
  return fixture;
}
