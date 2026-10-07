import { isIP } from 'node:net';
import { BLOCK_AT } from './decide.mjs';

export const RULE_TTL_SECONDS = 3600;
const MAX_TTL_SECONDS = 86400;
const MAX_EVIDENCE = 10;

function isInternal(ip) {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  const v6 = ip.toLowerCase();
  return v6 === '::1' || v6 === '::' || /^f[cd]/u.test(v6) || /^fe[89ab]/u.test(v6);
}

// Collects deny rules (block candidates only) and alert log lines. Nothing here edits the decider's own rules.
export function createBridge({ allowlist = [], ttlSeconds = RULE_TTL_SECONDS } = {}) {
  const ttl = Math.min(Math.max(Math.floor(ttlSeconds), 1), MAX_TTL_SECONDS);
  const rules = new Map();
  const logLines = [];
  const downgraded = [];

  function refuse(row, decision) {
    if (decision.confidence < BLOCK_AT) return '확신도가 차단 기준 미만';
    if (!row.srcip) return '출발 주소 없음';
    if (allowlist.includes(row.srcip)) return '허용 목록 주소';
    if (isInternal(row.srcip)) return '내부망·예약 주소는 자동 차단하지 않음';
    return null;
  }

  function handle(row, decision) {
    let { action, reason } = decision;
    if (action === 'block') {
      const why = refuse(row, decision);
      if (why) {
        action = 'alert';
        reason = `${reason} [자동 차단 제외: ${why}]`;
        downgraded.push({ alertId: row.alertId, why });
      } else {
        const at = Date.parse(row.at);
        const old = rules.get(row.srcip);
        if (old && Date.parse(old.expiresAt) > at) {
          if (old.evidenceAlertIds.length < MAX_EVIDENCE) old.evidenceAlertIds.push(row.alertId);
        } else {
          rules.set(row.srcip, {
            id: `xdr.bruteforce.${row.srcip.replace(/[^a-z0-9.]/giu, '_')}`, effect: 'deny', match: { srcip: row.srcip },
            createdAt: new Date(at).toISOString(), expiresAt: new Date(at + ttl * 1000).toISOString(),
            evidenceAlertIds: [row.alertId], patternId: reason.split(':')[0], confidence: decision.confidence,
          });
        }
      }
    }
    if (action !== 'record') {
      logLines.push(JSON.stringify({ at: row.at, action: action.toUpperCase(), alertId: row.alertId, srcip: row.srcip,
        account: row.account, confidence: decision.confidence, reason }));
    }
    return { action, reason };
  }

  return { handle, rules: () => [...rules.values()], logLines: () => [...logLines], downgraded: () => [...downgraded] };
}
