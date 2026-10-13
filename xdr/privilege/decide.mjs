// Standalone, pure classification. Keep PATTERNS synchronized with patterns.json.
// 근거: MITRE ATT&CK T1068 (권한 상승 악용), T1078 (정상 계정 도용). 기준 숫자는 학습용 가정입니다.
// 계정·주소·그룹 이름은 패턴 확인에만 쓰고 reason 에는 넣지 않습니다. 파일을 읽거나 쓰지 않고 바깥에 묻지 않습니다.
const PATTERNS = Object.freeze([
  { name: 'pv_admin_group_add' },
  { name: 'pv_unusual_admin_command' },
  { name: 'pv_offhours_privilege_use' },
  { name: 'pv_unconfirmed' },
  { name: 'pv_normal' },
]);

const BLOCK_LEVEL = 10;  // 규칙 수준이 이 값 이상이고 서로 다른 근거가 2가지 이상이면 명확한 권한 가로채기
const ALERT_LEVEL = 5;   // 권한 신호가 있고 수준이 이 값 이상이면 알림 후보
const BLOCK_EVIDENCE = 2;

// 근거 종류마다 한 번만 센다. 수준 하나나 설명 문장 하나만으로는 차단하지 않는다.
const EVIDENCE = Object.freeze([
  ['admin_group', /관리자 그룹(?:에|으로)\s*(?:추가|들어)|관리자 그룹 추가|다시 관리자로 들어/u],
  ['admin_command', /관리자 명령|권한 명령|명령 실행/u],
  ['new_origin', /처음 (?:보는|봅니다)|원격 주소/u],
  ['off_hours', /수업 시간 밖|업무처럼 보이지 않|업무 시간 밖/u],
  ['just_elevated', /관리자 권한으로 바뀌|방금 관리자/u],
  ['borrowed', /다른 계정의 권한/u],
]);
const ADMIN_GROUP_NAME = /^(?:administrators?|admins?|domain admins)$/iu;
const SIGNAL = /관리자 그룹|관리자 명령|관리자 권한|권한 상승|권한 명령|그룹에 (?:추가|들어)/u;
const MITRE = /^T(?:1068|1078|1548)(?:\.\d{3})?$/u;

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
    return decision(0.5, 'pv_unconfirmed', '자료가 불완전한 사건, 알림만 남김');
  }
  const description = typeof alert.rule.description === 'string' ? alert.rule.description.slice(0, 2000) : '';
  const group = typeof alert.data.group === 'string' ? alert.data.group.slice(0, 128) : '';
  const level = Number.isFinite(Number(alert.rule.level)) ? Number(alert.rule.level) : 0;
  const count = Number.isFinite(Number(alert.data.count)) ? Number(alert.data.count) : 1;
  const mitre = Array.isArray(alert.rule.mitre) && alert.rule.mitre.some(id => MITRE.test(String(id)));
  const signal = mitre || SIGNAL.test(description);

  // 1) 권한 변경·사용 신호가 없으면 정상 이벤트
  if (!signal) return decision(0.05, 'pv_normal', '권한 상승 신호가 없는 일반 이벤트');

  const found = EVIDENCE.filter(([, pattern]) => pattern.test(description)).map(([key]) => key);
  if (ADMIN_GROUP_NAME.test(group) && !found.includes('admin_group')) found.push('admin_group');
  if (count >= 2) found.push('repeated');
  const evidence = found.length;

  // 2) 수준이 낮으면 신호가 있어도 정상 이벤트
  if (level < ALERT_LEVEL) return decision(0.05, 'pv_normal', '수준이 낮은 일반 이벤트');

  // 3) 명확한 권한 가로채기: 높은 규칙 수준 + 서로 다른 근거 2가지 이상 → block
  if (level >= BLOCK_LEVEL && evidence >= BLOCK_EVIDENCE) {
    const name = found.includes('off_hours') ? 'pv_offhours_privilege_use'
      : ['admin_command', 'just_elevated', 'borrowed'].some(key => found.includes(key))
        ? 'pv_unusual_admin_command' : 'pv_admin_group_add';
    const confidence = clamp(0.86 + 0.03 * (evidence - BLOCK_EVIDENCE) + 0.01 * Math.min(level - BLOCK_LEVEL, 3), 0.99);
    return decision(confidence, name, `근거 ${evidence}가지가 겹침, 규칙 수준 ${level} (T1068/T1078)`);
  }

  // 4) 애매함: 권한 신호는 있으나 근거가 부족 → alert
  const confidence = clamp(0.5 + 0.05 * Math.min(evidence, 3) + 0.01 * Math.max(0, Math.min(level - ALERT_LEVEL, 5)), 0.8);
  return decision(confidence, 'pv_unconfirmed', `권한 신호는 있으나 근거 ${evidence}가지, 알림만 남김`);
}
