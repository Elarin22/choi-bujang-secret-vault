import { findRule } from '../brute-force/gate.mjs';

// 판정기에 확인 단계로 꽂을 수 있는 부품. 허용 결정은 만들지 않고, 일치하는 거부 규칙만 알려 준다.
// 현재 판정 요청 계약에는 출발 주소가 없어서 sourceOf 는 엔진이 주는 값으로 채워야 하며, src/decider.mjs 에는 아직 연결하지 않았다.
export function webInjectionStep(request, { rules, now = Date.now(), sourceOf = () => null } = {}) {
  const rule = findRule(sourceOf(request)?.srcip, rules, now);
  return rule ? { hit: true, ruleId: rule.id, expiresAt: rule.expiresAt, evidenceAlertIds: rule.evidenceAlertIds } : null;
}
