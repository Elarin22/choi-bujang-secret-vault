import { applyDenyRules, RULE_TTL_SECONDS } from '../shared.mjs';

export { RULE_TTL_SECONDS };
// decide 결과 중 block 의 출발 주소만 ZTNA 거부 규칙 후보(xdr/known-cve/ztna-deny-rules.json)로 만들고,
// 알림은 xdr/alerts.log 에 한 줄씩 쌓는다. 규칙에는 만료 시각과 근거 경보 번호가 붙는다.
// 내부망·예약 주소와 허용 목록 주소는 정상 사용자일 수 있어 규칙을 만들지 않고 알림만 남긴다. 판정기의 기존 규칙은 고치지 않는다.
export function applyActions({ root, alerts, decisions, now, ttlSeconds }) {
  return applyDenyRules({ root, moduleKey: 'known-cve', alerts, decisions, now, ttlSeconds });
}
export { applyActions as respond };
