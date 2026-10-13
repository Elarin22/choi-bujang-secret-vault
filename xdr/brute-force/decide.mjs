// Standalone, pure classification. Keep PATTERNS synchronized with patterns.json.
// 근거: MITRE ATT&CK T1543 (시스템 프로세스 생성·변경), T1053 (예약 작업). 기준 숫자는 학습용 가정입니다.
// 경로·서명 값·출발 주소는 패턴 확인에만 쓰고 reason 에는 넣지 않습니다. 파일을 읽거나 쓰지 않고 바깥에 묻지 않습니다.
const PATTERNS = Object.freeze([
  { name: 'ps_unsigned_new_service' },
  { name: 'ps_unsigned_scheduled_task' },
  { name: 'ps_startup_location_change' },
  { name: 'ps_unconfirmed' },
  { name: 'ps_normal' },
]);

const BLOCK_LEVEL = 10;  // 규칙 수준이 이 값 이상이고 서로 다른 근거가 2가지 이상이면 명확한 지속성 심기
const ALERT_LEVEL = 5;   // 지속성 신호가 있고 수준이 이 값 이상이면 알림 후보
const BLOCK_EVIDENCE = 2;

// 근거 종류마다 한 번만 센다. 설명 문장 하나나 수준 하나만으로는 차단하지 않는다.
const EVIDENCE = Object.freeze([
  ['unsigned', /서명(?:이|은|도)?\s*없/u],
  ['unlisted', /처음 보는|평소 목록에 없|목록에 없는|낯선/u],
  ['temp', /임시 폴더|[\\/](?:temp|tmp)[\\/]/iu],
  ['startup', /시작 폴더|시작 프로그램|시작 항목|startup[\\/]/iu],
  ['survives', /다시 켜도|재부팅|로그온|부팅/u],
  ['changed', /실행 파일이 바뀌/u],
  ['random', /임의 문자열/u],
]);
const REPEAT = /연속|반복/u;
const SIGNAL = /서비스|예약 작업|시작 폴더|시작 프로그램|시작 항목/u;
const MITRE = /^T(?:1543|1053|1547)(?:\.\d{3})?$/u;
const BENIGN = /서명된|읽기만|평소 (?:시각|저장소)|평소 목록(?:대로|에 있)|목록에 있는/u;
const STARTUP = /시작 폴더|시작 프로그램|시작 항목|startup[\\/]/iu;
const TASK = /예약 작업/u;

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const clamp = (value, max) => Math.min(max, Math.round(value * 100) / 100);

function decision(confidence, name, detail) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason: `${name}: ${detail}`,
  };
}

export function decide(alert) {
  if (!object(alert) || !object(alert.rule) || !object(alert.data)) {
    return decision(0.5, 'ps_unconfirmed', '자료가 불완전한 사건, 알림만 남김');
  }
  const description = typeof alert.rule.description === 'string' ? alert.rule.description.slice(0, 2000) : '';
  const path = typeof alert.data.path === 'string' ? alert.data.path.slice(0, 512) : '';
  const text = `${description}\n${path}`;
  const level = Number.isFinite(Number(alert.rule.level)) ? Number(alert.rule.level) : 0;
  const count = Number.isFinite(Number(alert.data.count)) ? Number(alert.data.count) : 1;
  const mitre = Array.isArray(alert.rule.mitre) && alert.rule.mitre.some(id => MITRE.test(String(id)));
  const signal = mitre || SIGNAL.test(description);

  // 1) 지속성 신호가 없으면 정상 이벤트
  if (!signal) return decision(0.05, 'ps_normal', '지속성 등록·변경 신호가 없음');

  const found = EVIDENCE.filter(([, pattern]) => pattern.test(text)).map(([key]) => key);
  if (count >= 2 || REPEAT.test(description)) found.push('repeated');
  const evidence = found.length;

  // 2) 서명됨·평소 목록대로·읽기만 같은 정상 표시가 있고 수준이 낮으면 정상 이벤트
  if (level < BLOCK_LEVEL && (BENIGN.test(description) || level < ALERT_LEVEL && evidence < BLOCK_EVIDENCE)) {
    return decision(0.05, 'ps_normal', '평소 목록·서명 확인된 정상 등록이거나 수준이 낮음');
  }

  // 3) 명확한 지속성 심기: 높은 규칙 수준 + 서로 다른 근거 2가지 이상 → block
  if (level >= BLOCK_LEVEL && evidence >= BLOCK_EVIDENCE) {
    const name = STARTUP.test(text) ? 'ps_startup_location_change'
      : TASK.test(description) ? 'ps_unsigned_scheduled_task' : 'ps_unsigned_new_service';
    const confidence = clamp(0.86 + 0.03 * (evidence - BLOCK_EVIDENCE) + 0.01 * Math.min(level - BLOCK_LEVEL, 3), 0.99);
    return decision(confidence, name, `근거 ${evidence}가지가 겹침, 규칙 수준 ${level} (T1543/T1053)`);
  }

  // 4) 애매함: 지속성 신호는 있으나 근거가 부족 → alert
  const confidence = clamp(0.5 + 0.05 * Math.min(evidence, 3) + 0.01 * Math.max(0, Math.min(level - ALERT_LEVEL, 5)), 0.8);
  return decision(confidence, 'ps_unconfirmed', `지속성 신호는 있으나 근거 ${evidence}가지, 알림만 남김`);
}
