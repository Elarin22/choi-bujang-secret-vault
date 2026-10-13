// 9단계 탐지 함수: 반 엔진이 검증해 넘긴 사건에서 가명 주체(identity.sub)·요청 종류(method)·시각(at)만 읽습니다.
// 메모 내용·토큰·실명 같은 다른 값은 읽지도, 저장하지도, 출력하지도 않습니다.
// 같은 sub의 GET이 어느 10분 구간에서든 120건을 넘을 때만 회수 제안을 돌려줍니다(정확히 120건은 관찰).
// 이 파일은 제안만 만들 뿐 회수 API를 부르거나 기기 권한을 바꾸지 않습니다. 실제 회수와 시간은 심판이 확인합니다.
export const BURST_WINDOW_MS = 10 * 60 * 1000;
export const BURST_LIMIT = 120;
const MAX_SUB_LENGTH = 128;

// 입력 정리: 형식이 맞지 않는 사건은 세지 않고 건너뜁니다. 필요한 세 값만 새 객체에 복사합니다.
function readEvent(raw) {
  if (raw === null || typeof raw !== 'object') return null;
  const { at, method, identity } = raw;
  const sub = identity !== null && typeof identity === 'object' ? identity.sub : undefined;
  if (method !== 'GET' || typeof sub !== 'string' || !sub || sub.length > MAX_SUB_LENGTH) return null;
  if (typeof at !== 'string') return null;
  const time = Date.parse(at);
  return Number.isFinite(time) ? { sub, time } : null;
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  // 사용자별로 따로 모읍니다. 다른 사용자의 사건은 합산하지 않습니다.
  const bySub = new Map();
  for (const raw of events) {
    const event = readEvent(raw);
    if (!event) continue;
    if (!bySub.has(event.sub)) bySub.set(event.sub, []);
    bySub.get(event.sub).push(event.time);
  }
  let found = null;
  for (const [sub, times] of bySub) {
    if (times.length <= BURST_LIMIT) continue;
    times.sort((a, b) => a - b);
    // 미끄러지는 10분 구간: 구간은 [시작, 시작+10분) 이라 정확히 10분 떨어진 사건은 같은 묶음이 아닙니다.
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] >= BURST_WINDOW_MS) start += 1;
      if (end - start + 1 > BURST_LIMIT) {
        if (!found || times[end] < found.time) found = { sub, time: times[end] };
        break;
      }
    }
  }
  return found ? { action: 'propose_revocation', reasonCode: 'burst_read', subject: found.sub } : { action: 'observe' };
}
