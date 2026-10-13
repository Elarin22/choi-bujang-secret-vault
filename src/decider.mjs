// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// 규칙을 하나씩 추가하며, RULE_IDS에는 실제로 구현한 규칙 이름만 둡니다.
export const RULE_IDS = Object.freeze(['device_registered']);

// 6단계 device_registered: 엔진이 확인한 요청의 deviceRegistered가 true일 때만 허용하고,
// false이거나 값이 없으면 거부합니다.
export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  return {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}
