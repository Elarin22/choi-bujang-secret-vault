import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';

export const RULE_TTL_SECONDS = 3600;
const MAX_EVIDENCE = 10;

function isInternal(ip) {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  const v6 = ip.toLowerCase();
  return v6 === '::1' || v6 === '::' || /^f[cd]/u.test(v6) || /^fe[89ab]/u.test(v6);
}

async function readAllowlist(root) {
  try {
    const list = JSON.parse(await readFile(join(root, 'xdr', 'brute-force', 'allowlist.json'), 'utf8')).srcips;
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

// block 결정 중 "명확한 공격"의 출발 주소만 거부 규칙으로 만듭니다.
// 규칙에는 만료 시각과 근거 경보 번호가 붙습니다. 만료는 경보 시각이 아니라 이번 실행 시각 기준입니다.
// 내부망·예약 주소와 허용 목록 주소는 자동 차단하지 않고 알림(alerts.log)만 남깁니다.
export async function applyActions({ root, alerts, decisions, now = Date.now(), ttlSeconds = RULE_TTL_SECONDS }) {
  const byId = new Map(alerts.map((alert) => [alert.id, alert]));
  const allow = await readAllowlist(root);
  const createdAt = new Date(now).toISOString();
  const expiresAt = new Date(now + ttlSeconds * 1000).toISOString();
  const bySource = new Map();
  const skipped = [];
  for (const decision of decisions) {
    if (decision.action !== 'block') continue;
    const srcip = byId.get(decision.alertId)?.data?.srcip;
    if (typeof srcip !== 'string' || isIP(srcip) === 0) { skipped.push({ alertId: decision.alertId, why: '출발 주소 없음' }); continue; }
    if (allow.includes(srcip)) { skipped.push({ alertId: decision.alertId, why: '허용 목록 주소' }); continue; }
    if (isInternal(srcip)) { skipped.push({ alertId: decision.alertId, why: '내부망·예약 주소' }); continue; }
    const rule = bySource.get(srcip);
    if (rule) {
      if (rule.evidenceAlertIds.length < MAX_EVIDENCE) rule.evidenceAlertIds.push(decision.alertId);
    } else {
      bySource.set(srcip, { id: `brute-force-${decision.alertId}`, action: 'deny', effect: 'deny', sourceIp: srcip,
        match: { srcip }, createdAt, expiresAt, evidenceAlertId: decision.alertId, evidenceAlertIds: [decision.alertId],
        reason: decision.reason, confidence: decision.confidence });
    }
  }
  const rules = [...bySource.values()];
  const dir = join(root, 'xdr', 'brute-force');
  await mkdir(dir, { recursive: true });
  const body = `${JSON.stringify({ schema: 'aleph.xdr.ztna-rules.v1', rules }, null, 2)}\n`;
  await writeFile(join(dir, 'ztna-deny-rules.json'), body, 'utf8');
  await writeFile(join(dir, 'deny-rules.json'), body, 'utf8');

  const skippedIds = new Set(skipped.map((item) => item.alertId));
  const lines = decisions.filter((item) => item.action !== 'record').map((item) => JSON.stringify({
    alertId: item.alertId, action: skippedIds.has(item.alertId) ? 'alert' : item.action, confidence: item.confidence,
    reason: skippedIds.has(item.alertId) ? `${item.reason} [자동 차단 제외: ${skipped.find((s) => s.alertId === item.alertId).why}]` : item.reason,
  }));
  await writeFile(join(root, 'xdr', 'alerts.log'), lines.length ? `${lines.join('\n')}\n` : '', 'utf8');
  return rules;
}
