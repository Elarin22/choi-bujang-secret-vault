// 단일 파일 판정 모듈: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다.
// 입력: Wazuh 원본 경보, 또는 {id, sourceIp, level, ...} 요약.
// 근거: MITRE ATT&CK T1543(시스템 프로세스 생성·변경), T1053(예약 작업). 기준 숫자는 학습용 가정입니다.
// 파일 경로·서명 값은 패턴 확인에만 쓰고 reason 에는 넣지 않습니다.

// xdr/persistence/patterns.json 의 패턴 (이름·근거)
const PATTERNS = Object.freeze({
  unsigned_new_service: { name: '서명 없는 새 서비스 등록', evidence: 'T1543 자동 시작 서비스 신호' },
  unsigned_scheduled_task: { name: '서명 없는 낯선 예약 작업', evidence: 'T1053 로그온·부팅 예약 작업 신호' },
  startup_location_change: { name: '시작 폴더에 서명 없는 항목 생성·변경', evidence: 'T1543 계열 로그인 자동 실행 신호' },
});

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const BLOCK_LEVEL = 10;   // 규칙 수준 이 값 이상이면 명확한 공격 후보
const REPEAT_COUNT = 2;   // 같은 항목이 이 횟수 이상 반복되면 확신도를 더 올림

const STARTUP_PATH = /(?:\\|\/)(?:startup|시작 프로그램)(?:\\|\/)|\\(?:run|runonce)$/iu;
const SERVICE_EVENT = /^(?:service_created|service|svc)$/iu;
const TASK_EVENT = /^(?:task_created|scheduled_task|task)$/iu;
const FILE_EVENT = /^(?:file_changed|file_created|integrity|syscheck)$/iu;
const SERVICE_WORD = /서비스|service/iu;
const TASK_WORD = /예약 작업|scheduled task|schtasks/iu;
const UNSIGNED_WORD = /서명 없는|unsigned/iu;
// "서명 없는 서비스가 아닙니다" 처럼 서명 없음 자체를 부정하는 문장만 제외한다 ("이벤트 자료는 없습니다"는 제외 대상이 아님)
const NEGATED = /서명 없는[^.]{0,20}(?:아닙니다|아니다)/u;

function flatten(value, depth = 0) {
  if (value == null || depth > 4) return [];
  if (typeof value === 'string') return [value];
  if (typeof value === 'number' || typeof value === 'boolean') return [String(value)];
  if (Array.isArray(value)) return value.flatMap((item) => flatten(item, depth + 1));
  if (typeof value === 'object') return Object.values(value).flatMap((item) => flatten(item, depth + 1));
  return [];
}

function normalizeAlert(alert) {
  const a = alert && typeof alert === 'object' ? alert : {};
  const data = a.data && typeof a.data === 'object' ? a.data : {};
  const description = String(a.rule?.description ?? a.description ?? '');
  const level = Number(a.rule?.level ?? a.level ?? 0);
  const countRaw = Number(data.count ?? a.count ?? 0);
  const event = String(data.event ?? a.event ?? '').toLowerCase();
  const path = String(data.path ?? a.path ?? '');
  return {
    id: String(a.id ?? a.alertId ?? ''),
    description,
    level: Number.isFinite(level) ? level : 0,
    count: Number.isFinite(countRaw) && countRaw >= 0 ? countRaw : 0,
    event,
    path,
    // 서명 여부: 명시된 true/false만 쓴다. 값이 없으면 알 수 없음(undefined).
    signed: typeof data.signed === 'boolean' ? data.signed : (typeof a.signed === 'boolean' ? a.signed : undefined),
    listed: String(data.baseline ?? a.baseline ?? '').toLowerCase() === 'listed',
    autostart: data.autostart === true || a.autostart === true || STARTUP_PATH.test(path),
  };
}

const done = (confidence, patternId, note) => ({
  action: confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record',
  confidence,
  reason: patternId ? `${patternId}: ${PATTERNS[patternId].name} - ${note} (${PATTERNS[patternId].evidence})` : `normal_persistence: ${note}`,
});

// 반환: { action: 'block'|'alert'|'record', confidence: 0~1, reason: string(근거 패턴 이름 포함) }
export function decide(alert) {
  const item = normalizeAlert(alert);
  if (!item.description && !item.event && !item.path) return { action: 'record', confidence: 0, reason: 'invalid_alert: 내용이 없는 경보' };

  const negated = NEGATED.test(item.description);
  // 이벤트 자료가 있으면 그것으로 종류를 정하고, 없을 때만 설명 문장을 읽는다 (설명만으로는 차단하지 않는다).
  let kind = null;
  if (SERVICE_EVENT.test(item.event)) kind = 'unsigned_new_service';
  else if (TASK_EVENT.test(item.event)) kind = 'unsigned_scheduled_task';
  else if (FILE_EVENT.test(item.event) && (item.autostart || STARTUP_PATH.test(item.path))) kind = 'startup_location_change';

  if (kind) {
    const unsigned = item.signed === false;
    // 1) 명확한 공격: 서명 없음 + 평소 목록에 없음 + 자동 시작 + 높은 규칙 수준 → block
    if (unsigned && !item.listed && item.autostart && item.level >= BLOCK_LEVEL) {
      const confidence = item.count >= REPEAT_COUNT ? 0.95 : 0.9;
      return done(confidence, kind, `규칙 수준 ${item.level}, 서명 없음·평소 목록 없음·자동 시작${item.count >= REPEAT_COUNT ? `, ${item.count}회 반복` : ''}`);
    }
    // 2) 애매함: 평소 목록에 없고 서명을 확인하지 못했거나 서명 없음 → alert
    if (!item.listed && item.signed !== true) {
      return done(0.6, kind, `규칙 수준 ${item.level}, 자동 시작 ${item.autostart ? '예' : '아니오'}, 근거 부족`);
    }
    // 3) 서명됐거나 평소 목록에 있음 → 정상
    return done(0.05, null, `서명됨 또는 평소 목록에 있음 (규칙 수준 ${item.level})`);
  }

  // 이벤트 자료 없이 설명 문장만 있는 경우: 알림까지만
  if (!negated && (UNSIGNED_WORD.test(item.description) && (SERVICE_WORD.test(item.description) || TASK_WORD.test(item.description)))) {
    const pattern = TASK_WORD.test(item.description) ? 'unsigned_scheduled_task' : 'unsigned_new_service';
    return done(0.5, pattern, '설명 문장만 있고 이벤트 자료가 없어 알림까지만');
  }

  // 정상 이벤트 (서명됐거나 평소 목록에 있는 일반 변경)
  return done(item.level <= 3 ? 0.05 : 0.1, null, '알려진 지속성 형태 아님');
}
