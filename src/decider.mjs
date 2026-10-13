// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
// 규칙을 하나씩 추가하며, RULE_IDS에는 실제로 구현한 규칙 이름만 둡니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'exact_route_only', 'own_notes_zone', 'notice_zone', 'write_not_allowed']);

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

// 8단계 구역 규칙: 전체 목록은 거부하고 /my/notes(내 메모)만 허용합니다.
// 엔진이 확인한 method·route·path만 정확히 대조합니다. 알 수 없는 경로는 거부합니다.
// 쿼리는 보지 않습니다(자료 ID만 고르고 기능은 경로로만 고름). :id 자리에 export 같은 기능 이름은 받지 않습니다.
// 이 요청 계약에는 소유자와 강사 역할이 없어서, 남의 메모 차단과 강사 확인은 자료 API가 저장된 값으로 다시 합니다.
const RESERVED_IDS = Object.freeze(['export', 'import', 'search', 'list', 'all', 'admin', 'new', 'bulk', 'download', 'upload']);
const ID = '[A-Za-z0-9][A-Za-z0-9_-]{0,63}';
const ROUTES = Object.freeze([
  // 전체 메모 목록(GET /notes)은 열지 않습니다. 목록은 본인 전용 경로 /my/notes로만 받습니다.
  ['GET', '/my/notes', 'own_notes'], ['GET', '/notes/:id', 'own_notes'],
  ['GET', '/notices', 'notice_read'], ['GET', '/notices/:id', 'notice_read'],
].map(([method, template, zone]) => Object.freeze({ method, template, zone,
  regex: new RegExp(`^${template.replace(':id', `(${ID})`)}$`, 'u') })));

// 쓰기(추가·수정·삭제)는 엔진 요청 계약에 소유자·강사 정보가 없어 판정기가 허용할 근거가 없습니다.
// 그래서 판정기에서는 거부하고, 자료 API가 검증된 사용자와 저장된 소유자·강사 권한으로 다시 판단합니다.
const WRITE_METHODS = Object.freeze(['POST', 'PUT', 'PATCH', 'DELETE']);

export function matchRoute(request) {
  const { method, route, path } = request ?? {};
  if (typeof method !== 'string' || typeof route !== 'string' || typeof path !== 'string' || path.length > 200) return null;
  const strip = (value) => value.replace(/^(\S+ )?\/api(?=\/)/u, '$1');
  const cleanRoute = strip(route);
  const cleanPath = strip(path);
  if (/[?#\\]|\/\/|\.\./u.test(cleanPath)) return null;
  for (const entry of ROUTES) {
    if (entry.method !== method || cleanRoute !== `${entry.method} ${entry.template}`) continue;
    const match = entry.regex.exec(cleanPath);
    if (!match) continue;
    if (match[1] && RESERVED_IDS.includes(match[1].toLowerCase())) return null;
    return entry;
  }
  return null;
}

// 6단계 device_registered: deviceRegistered가 true일 때만 허용합니다.
// 7단계 step_up_required: 위험 조합이면 다시 확인을 요구하고, 엔진이 확인한 재인증(stepUp)이 있으면 허용합니다.
export async function decide(request) {
  const base = { schema: 'aleph.decision.v1', requestId: request?.requestId };
  if (request?.deviceRegistered !== true) {
    return { ...base, decision: 'deny', reasonCode: 'device_not_registered', ruleIds: ['device_registered'] };
  }
  if (WRITE_METHODS.includes(request?.method)) {
    return { ...base, decision: 'deny', reasonCode: 'write_not_allowed', ruleIds: ['write_not_allowed'] };
  }
  const hit = matchRoute(request);
  if (!hit || request.service !== 'notes' || request.queryLength !== 0) {
    return { ...base, decision: 'deny', reasonCode: 'route_not_allowed', ruleIds: ['exact_route_only'] };
  }
  const zoneRule = hit.zone === 'own_notes' ? 'own_notes_zone' : 'notice_zone';
  if (describeRisk(request).risky) {
    return reverified(request)
      ? { ...base, decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered', 'step_up_required', zoneRule] }
      : { ...base, decision: 'step_up', reasonCode: 'step_up_required', ruleIds: ['step_up_required'] };
  }
  return { ...base, decision: 'allow', reasonCode: 'approved', ruleIds: ['device_registered', zoneRule] };
}
