import { applyDenyRules, RULE_TTL_SECONDS } from '../shared.mjs';

export { RULE_TTL_SECONDS };
// block 결정의 출발 주소를 만료 시각·근거 경보 번호가 붙은 거부 규칙으로 만들고 알림을 남긴다.
export function applyActions({ root, alerts, decisions, now, ttlSeconds }) {
  return applyDenyRules({ root, moduleKey: 'brute-force', alerts, decisions, now, ttlSeconds, legacyFile: true });
}
