// brute-force 와 web-injection 이 함께 쓰는 연결 부품: 거부 규칙 만들기 + 알림 기록.
// 판정기(src/decider.mjs)의 기존 규칙은 고치지 않고, 여기서는 "거부 규칙 후보"만 만든다.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';

export const RULE_TTL_SECONDS = 3600;
const MAX_EVIDENCE = 10;

export function isInternal(ip) {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  const v6 = ip.toLowerCase();
  return v6 === '::1' || v6 === '::' || /^f[cd]/u.test(v6) || /^fe[89ab]/u.test(v6);
}

async function readAllowlist(root, moduleKey) {
  try {
    const list = JSON.parse(await readFile(join(root, 'xdr', moduleKey, 'allowlist.json'), 'utf8')).srcips;
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

// 알림은 xdr/alerts.log 에 한 줄씩 쌓는다. 같은 모듈의 이전 줄만 새로 바꾸고 다른 모듈의 줄은 남긴다.
// module 표시가 없는 옛 줄은 brute-force 것으로 본다.
async function writeAlertLog(root, moduleKey, lines) {
  const path = join(root, 'xdr', 'alerts.log');
  let kept = [];
  try {
    kept = (await readFile(path, 'utf8')).split(/\r?\n/u).filter((line) => {
      if (!line.trim()) return false;
      try { return (JSON.parse(line).module ?? 'brute-force') !== moduleKey; } catch { return true; }
    });
  } catch { /* 첫 실행 */ }
  const all = [...kept, ...lines.map((line) => JSON.stringify({ module: moduleKey, ...line }))];
  await writeFile(path, all.length ? `${all.join('\n')}\n` : '', 'utf8');
}

// block 결정 중 출발 주소가 있는 것만 거부 규칙 후보로 만든다.
// 규칙에는 만료 시각(이번 실행 시각 + ttl)과 근거 경보 번호가 붙는다.
// 내부망·예약 주소와 허용 목록 주소는 정상 사용자일 수 있으므로 규칙을 만들지 않고 알림만 남긴다.
export async function applyDenyRules({ root, moduleKey, alerts, decisions, now = Date.now(), ttlSeconds = RULE_TTL_SECONDS, legacyFile = false }) {
  const byId = new Map(alerts.map((alert) => [alert.id, alert]));
  const allow = await readAllowlist(root, moduleKey);
  const createdAt = new Date(now).toISOString();
  const expiresAt = new Date(now + ttlSeconds * 1000).toISOString();
  const bySource = new Map();
  const skipped = new Map();
  for (const decision of decisions) {
    if (decision.action !== 'block') continue;
    const srcip = byId.get(decision.alertId)?.data?.srcip;
    if (typeof srcip !== 'string' || isIP(srcip) === 0) { skipped.set(decision.alertId, '출발 주소 없음'); continue; }
    if (allow.includes(srcip)) { skipped.set(decision.alertId, '허용 목록 주소'); continue; }
    if (isInternal(srcip)) { skipped.set(decision.alertId, '내부망·예약 주소'); continue; }
    const rule = bySource.get(srcip);
    if (rule) {
      if (rule.evidenceAlertIds.length < MAX_EVIDENCE) rule.evidenceAlertIds.push(decision.alertId);
    } else {
      bySource.set(srcip, { id: `${moduleKey}-${decision.alertId}`, action: 'deny', effect: 'deny', sourceIp: srcip,
        match: { srcip }, createdAt, expiresAt, evidenceAlertId: decision.alertId, evidenceAlertIds: [decision.alertId],
        reason: decision.reason, confidence: decision.confidence });
    }
  }
  const rules = [...bySource.values()];
  const dir = join(root, 'xdr', moduleKey);
  await mkdir(dir, { recursive: true });
  const body = `${JSON.stringify({ schema: 'aleph.xdr.ztna-rules.v1', rules }, null, 2)}\n`;
  await writeFile(join(dir, 'ztna-deny-rules.json'), body, 'utf8');
  if (legacyFile) await writeFile(join(dir, 'deny-rules.json'), body, 'utf8');

  const lines = decisions.filter((item) => item.action !== 'record').map((item) => skipped.has(item.alertId)
    ? { alertId: item.alertId, action: 'alert', confidence: item.confidence, reason: `${item.reason} [자동 차단 제외: ${skipped.get(item.alertId)}]` }
    : { alertId: item.alertId, action: item.action, confidence: item.confidence, reason: item.reason });
  await writeAlertLog(root, moduleKey, lines);
  return rules;
}
