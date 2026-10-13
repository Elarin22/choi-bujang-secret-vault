// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// 규칙을 하나씩 추가하며, RULE_IDS에는 실제로 구현한 규칙 이름만 둡니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

// 7단계 입력 검사: 엔진이 검증해 넘긴 접속 신호의 출처만 믿습니다.
// 현재 실제 경로의 source는 'none'이라 신호를 쓰지 않고, 없는 값을 정상값으로 채우지도 않습니다.
const TRUSTED_SOURCES = Object.freeze(['judge_fixture']);
const UNUSUAL_HOURS = (hour) => hour < 7 || hour > 21;
const BURST_KINDS = Object.freeze(['risk_signal']);
const BURST_WINDOW_SECONDS = 600;
const BURST_COUNT = 10;
const MAX_STEP_UP_AGE_SECONDS = 900;

export function readSignals(request) {
  const s = request?.signals;
  if (!s || typeof s !== 'object' || !TRUSTED_SOURCES.includes(s.source)) return { trusted: false };
  const text = (value) => (typeof value === 'string' && value.length > 0 && value.length <= 32 ? value : null);
  return {
    trusted: true,
    region: text(s.region),
    network: text(s.network),
    hour: Number.isInteger(s.hour) && s.hour >= 0 && s.hour <= 23 ? s.hour : null,
  };
}

function recentReads(request) {
  if (!Array.isArray(request?.recentEvents)) return 0;
  return request.recentEvents.slice(0, 12).reduce((sum, event) => (event && BURST_KINDS.includes(event.kind)
    && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0 && event.ageSeconds <= BURST_WINDOW_SECONDS
    && Number.isInteger(event.count) && event.count > 0 ? sum + event.count : sum), 0);
}

// 시각·네트워크·갑작스러운 대량 읽기가 모두 겹칠 때만 위험합니다. 지역은 사유로만 남기고 단독 근거로 쓰지 않습니다.
export function describeRisk(request) {
  const signals = readSignals(request);
  if (!signals.trusted) return { risky: false, reasons: [] };
  const reasons = [];
  if (signals.hour !== null && UNUSUAL_HOURS(signals.hour)) reasons.push('unusual_hour');
  if (signals.network === 'unusual') reasons.push('unusual_network');
  if (recentReads(request) >= BURST_COUNT) reasons.push('sudden_bulk_reads');
  const risky = ['unusual_hour', 'unusual_network', 'sudden_bulk_reads'].every((reason) => reasons.includes(reason));
  if (signals.region && !['local', 'unknown'].includes(signals.region)) reasons.push('unfamiliar_region');
  return { risky, reasons };
}

const reverified = (request) => request?.stepUp?.verified === true
  && Number.isFinite(request.stepUp.authAgeSeconds)
  && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= MAX_STEP_UP_AGE_SECONDS;

// 6단계 device_registered: deviceRegistered가 true일 때만 허용합니다.
// 7단계 step_up_required: 위험 조합이면 다시 확인을 요구하고, 엔진이 확인한 재인증(stepUp)이 있으면 허용합니다.
export async function decide(request) {
  const base = { schema: 'aleph.decision.v1', requestId: request?.requestId };
  if (request?.deviceRegistered !== true) {
    return { ...base, decision: 'deny', reasonCode: 'device_not_registered', ruleIds: ['device_registered'] };
  }
  if (describeRisk(request).risky) {
    return reverified(request)
      ? { ...base, decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered', 'step_up_required'] }
      : { ...base, decision: 'step_up', reasonCode: 'step_up_required', ruleIds: ['step_up_required'] };
  }
  return { ...base, decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered'] };
}
