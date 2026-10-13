// Standalone, pure classification. Keep PATTERNS synchronized with patterns.json.
// 근거: MITRE ATT&CK T1543 (시스템 프로세스 생성·변경), T1053 (예약 작업). 기준 숫자는 학습용 가정입니다.
// 경로·서명 값은 패턴 확인에만 쓰고 reason 에는 넣지 않습니다. 파일을 읽거나 쓰지 않고 바깥에 묻지 않습니다.
const PATTERNS = Object.freeze([
  { name: 'ps_unsigned_new_service' },
  { name: 'ps_unsigned_scheduled_task' },
  { name: 'ps_startup_location_change' },
  { name: 'ps_unconfirmed' },
  { name: 'ps_normal' },
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const BLOCK_LEVEL = 10;  // 규칙 수준 이 값 이상이고 서명 없음·목록 밖·자동 시작이 모두 맞으면 명확한 지속성 심기
const REPEAT_COUNT = 2;  // 같은 항목이 이 횟수 이상 반복되면 확신도를 조금 올림

const SERVICE_EVENTS = new Set(['service_created', 'service', 'svc']);
const TASK_EVENTS = new Set(['task_created', 'scheduled_task', 'task']);
const FILE_EVENTS = new Set(['file_changed', 'file_created', 'integrity', 'syscheck']);
const STARTUP_PATH = /(?:startup|시작 프로그램|start menu)(?:[\\/]|$)/iu;
const WEAK_UNSIGNED = /서명 없는|unsigned/iu;
const WEAK_TARGET = /서비스|예약 작업|시작|service|task/iu;
// "서명 없는 서비스가 아닙니다" 처럼 서명 없음 자체를 부정하는 문장은 약한 신호로도 쓰지 않는다.
const NEGATED = /서명 없는[^.]{0,20}(?:아닙니다|아니다)/u;

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const flag = (value) => {
  if (value === true || value === 'True' || value === 'true') return true;
  if (value === false || value === 'False' || value === 'false') return false;
  return null;
};

function decision(confidence, name, detail) {
  return {
    action: confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record',
    confidence,
    reason: `${name}: ${detail}`,
  };
}

export function decide(alert) {
  if (!object(alert) || !object(alert.rule) || !object(alert.data)) {
    return decision(0.5, 'ps_unconfirmed', '자료가 불완전한 사건, 알림만 남김');
  }
  const data = alert.data;
  const event = typeof data.event === 'string' ? data.event.toLowerCase() : '';
  const path = typeof data.path === 'string' ? data.path.slice(0, 512) : '';
  const description = String(alert.rule.description ?? '').slice(0, 2000);
  const level = Number.isFinite(Number(alert.rule.level)) ? Number(alert.rule.level) : 0;
  const count = Number.isFinite(Number(data.count)) ? Number(data.count) : 1;

  const listed = data.baseline === 'listed';
  const unlisted = data.baseline === 'none';
  const signed = flag(data.signed);
  const unsigned = signed === false;
  const autostart = flag(data.autostart) === true;
  const isService = SERVICE_EVENTS.has(event);
  const isTask = TASK_EVENTS.has(event);
  const startup = FILE_EVENTS.has(event) && STARTUP_PATH.test(path);
  const persistenceEvent = isService || isTask || startup;
  const weakMention = !NEGATED.test(description) && WEAK_UNSIGNED.test(description) && WEAK_TARGET.test(description);
  const name = isService ? 'ps_unsigned_new_service' : isTask ? 'ps_unsigned_scheduled_task' : 'ps_startup_location_change';
  const label = isService ? '서명 없는 새 서비스 등록' : isTask ? '서명 없는 예약 작업' : '시작 위치의 서명 없는 항목';

  // 1) 평소 목록에 있는 항목은 운영 기준대로 정상 이벤트
  if (listed) return decision(0.05, 'ps_normal', '평소 목록에 있는 항목');

  // 2) 지속성 위치나 이벤트가 아닌 경우: 설명 문장만으로는 알림까지만
  if (!persistenceEvent) {
    if (weakMention) return decision(0.5, 'ps_unconfirmed', '설명 문장만 있고 이벤트 자료 없음, 알림만 남김');
    return decision(0.1, 'ps_normal', '지속성 위치나 이벤트가 아님');
  }

  // 3) 명확한 지속성 심기: 서명 없음 + 평소 목록 밖 + 자동 시작 + 높은 규칙 수준 → block
  if (unsigned && unlisted && autostart && level >= BLOCK_LEVEL) {
    const confidence = count >= REPEAT_COUNT ? 0.95 : 0.92;
    return decision(confidence, name, `${label}, 자동 시작, 규칙 수준 ${level}, 반복 ${count}번 (T1543/T1053)`);
  }

  // 4) 애매함: 목록 밖이지만 수준이 낮거나 자동 시작이 아니거나 서명 확인이 없음 → alert
  if (unlisted && (unsigned || signed === null || autostart)) {
    return decision(0.6, name, `${label}, 기준 미만 또는 확인 자료 부족, 알림만 남김`);
  }
  return decision(0.55, 'ps_unconfirmed', '목록 밖 지속성 이벤트, 근거 부족으로 알림만 남김');
}
