import { applyDenyRules, RULE_TTL_SECONDS } from '../shared.mjs';

export { RULE_TTL_SECONDS };
// 명확한 주입 공격(block)의 출발 주소만 거부 규칙 후보로 만든다. 판정기의 기존 규칙은 고치지 않는다.
export function applyActions({ root, alerts, decisions, now, ttlSeconds }) {
  return applyDenyRules({ root, moduleKey: 'web-injection', alerts, decisions, now, ttlSeconds });
}
