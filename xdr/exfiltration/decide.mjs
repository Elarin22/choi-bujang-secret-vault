// Standalone, pure classification. Keep PATTERNS synchronized with patterns.json.
// 근거: MITRE ATT&CK T1041 (명령 통로로 유출), T1048 (다른 프로토콜로 유출). 기준 숫자는 학습용 가정입니다.
// 주소·계정·파일 이름은 패턴 확인에만 쓰고 reason 에는 넣지 않습니다. 파일을 읽거나 쓰지 않고 바깥에 묻지 않습니다.
// 공식 경보는 data 값이 문자열이고(bytes "240000000"), protocol·file 필드가 없으므로 설명 문장과 숫자 필드를 함께 봅니다.
const PATTERNS = Object.freeze([
  { name: 'ex_new_destination_bulk' },
  { name: 'ex_offhours_archive' },
  { name: 'ex_alt_channel' },
]);
const UNCONFIRMED = 'ex_unconfirmed'; // 신호는 있으나 근거가 부족한 경우의 이름 (공격 패턴이 아님)
const NORMAL = 'ex_normal';            // 외부 전송 신호가 없는 정상 이벤트의 이름 (공격 패턴이 아님)

const BLOCK_LEVEL = 10;  // 규칙 수준이 이 값 이상이고 서로 다른 근거가 2가지 이상 겹치면 명확한 유출
const ALERT_LEVEL = 5;   // 외부 전송 신호가 있고 수준이 이 값 이상이면 알림 후보
const BLOCK_EVIDENCE = 2;
const LARGE_BYTES = 50 * 1000 * 1000; // 평소보다 큰 전송으로 보는 학습용 기준 (약 50MB)
const BULK_FILES = 50;                // 한 번에 많은 자료가 나갔다고 보는 학습용 기준 (50건)
const REPEAT_COUNT = 3;               // 반복 전송으로 보는 학습용 기준 (3번)

// 근거 종류마다 한 번만 센다. 수준 하나나 설명 문장 하나만으로는 차단하지 않는다.
const EVIDENCE = Object.freeze([
  ['new_destination', /처음 보는 (?:바깥 )?(?:주소|목적지)|새 목적지|목적지 (?:두|세|여러) /u],
  ['large_transfer', /평소보다 (?:훨씬 )?큰|대용량|큰 파일/u],
  ['bulk_files', /자료실 전체|전체가|묶음/u],
  ['off_hours', /수업 시간 밖|업무 시간 밖|업무처럼 보이지 않/u],
  ['archive', /압축 파일/u],
  ['alt_channel', /다른 프로토콜|쓰지 않던 포트|FTP|DNS 요청|ICMP/u],
  ['command_channel', /명령 통로|기존 연결/u],
  ['repeated', /반복|연속|\d+\s*번/u],
]);
const SIGNAL = /외부 전송|외부로|외부 주소|바깥 주소|목적지|전송|반출|올라갔|올렸|나갔|유출|명령 통로|복사/u;
const MITRE = /^T(?:1041|1048)(?:\.\d{3})?$/u;
const ARCHIVE_FILE = /\.(?:zip|7z|rar|tar|gz|tgz)$/iu;
const ALT_PROTOCOL = /^(?:ftp|dns|icmp)$/iu;

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const clamp = (value, max) => Math.min(max, Math.round(value * 100) / 100);
const number = value => (Number.isFinite(Number(value)) ? Number(value) : 0);

function decision(confidence, name, detail) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason: `${name}: ${detail}`,
  };
}

// 찾은 근거에서 가장 가까운 패턴 이름을 고른다.
function patternName(found) {
  if (found.includes('alt_channel')) return PATTERNS[2].name;
  if (found.includes('off_hours') && found.includes('archive')) return PATTERNS[1].name;
  return PATTERNS[0].name;
}

export function decide(alert) {
  if (!object(alert) || !object(alert.rule) || !object(alert.data)) {
    return decision(0.5, UNCONFIRMED, '자료가 불완전한 사건, 알림만 남김');
  }
  const description = typeof alert.rule.description === 'string' ? alert.rule.description.slice(0, 2000) : '';
  const file = typeof alert.data.file === 'string' ? alert.data.file.slice(0, 256) : '';
  const protocol = typeof alert.data.protocol === 'string' ? alert.data.protocol.slice(0, 16) : '';
  const bytes = number(alert.data.bytes);
  const files = number(alert.data.files);
  const level = number(alert.rule.level);
  const count = alert.data.count === undefined ? 1 : number(alert.data.count);
  const mitre = Array.isArray(alert.rule.mitre) && alert.rule.mitre.some(id => MITRE.test(String(id)));
  const signal = mitre || SIGNAL.test(description);

  // 1) 외부 전송 신호가 없으면 정상 이벤트
  if (!signal) return decision(0.05, NORMAL, '외부 전송 신호가 없는 일반 이벤트');

  // 2) 수준이 낮으면 신호가 있어도 정상 이벤트
  if (level < ALERT_LEVEL) return decision(0.05, NORMAL, '수준이 낮은 일반 이벤트');

  const found = EVIDENCE.filter(([, pattern]) => pattern.test(description)).map(([key]) => key);
  const add = key => { if (!found.includes(key)) found.push(key); };
  if (bytes >= LARGE_BYTES) add('large_transfer');
  if (files >= BULK_FILES) add('bulk_files');
  if (count >= REPEAT_COUNT) add('repeated');
  if (ARCHIVE_FILE.test(file)) add('archive');
  if (ALT_PROTOCOL.test(protocol)) add('alt_channel');
  const evidence = found.length;

  // 3) 명확한 유출: 높은 규칙 수준 + 서로 다른 근거 2가지 이상 → block
  if (level >= BLOCK_LEVEL && evidence >= BLOCK_EVIDENCE) {
    const confidence = clamp(0.86 + 0.03 * (evidence - BLOCK_EVIDENCE) + 0.01 * Math.min(level - BLOCK_LEVEL, 3), 0.99);
    return decision(confidence, patternName(found), `근거 ${evidence}가지가 겹침, 규칙 수준 ${level} (T1041/T1048)`);
  }

  // 4) 애매함: 외부 전송 신호는 있으나 근거가 부족하거나 수준이 낮음 → alert (차단하지 않는다)
  const confidence = clamp(0.5 + 0.05 * Math.min(evidence, 3) + 0.01 * Math.max(0, Math.min(level - ALERT_LEVEL, 5)), 0.8);
  return decision(confidence, evidence ? patternName(found) : UNCONFIRMED, `외부 전송 신호는 있으나 근거 ${evidence}가지, 알림만 남김`);
}
