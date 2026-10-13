// 단일 파일 판정 모듈: 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다.
// 입력: Wazuh 원본 경보, 또는 {id, sourceIp, level, count, description} 요약.
// 근거: CVE-2021-44228 형태 요청, MITRE ATT&CK T1190. 기준 숫자는 학습용 가정입니다.
// 요청 머리글·인자 원문은 패턴 확인에만 쓰고 reason 에는 넣지 않습니다.

// xdr/known-cve/patterns.json 의 패턴 (이름·근거)
const PATTERNS = Object.freeze({
  remote_lookup_in_header: { name: '요청 머리글 안의 원격 조회 구문(jndi 형태)', evidence: 'CVE-2021-44228 머리글 악용 신호' },
  remote_lookup_in_args: { name: '요청 인자 안의 원격 조회 구문(jndi 형태)', evidence: 'CVE-2021-44228 인자 악용 신호' },
  obfuscated_lookup: { name: '글자를 쪼갠 조회 구문(우회 표기)', evidence: 'CVE-2021-44228 우회 표기' },
  vuln_scanner_trace: { name: '알려진 취약점 점검 도구의 흔적', evidence: 'T1190 점검 도구 정찰 신호' },
  described_lookup_signal: { name: '경보 설명이 알려 주는 원격 조회 표기', evidence: 'CVE-2021-44228 형태 요청 경보 설명' },
});

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const BLOCK_LEVEL = 10;   // 규칙 수준 이 값 이상이면 명확한 공격 후보
const BLOCK_COUNT = 3;    // 요약 경보에서 같은 표기가 이 횟수 이상 반복

// 조회 구문 모양 (퍼센트 인코딩은 한 번 풀어서 본다)
const PLAIN_LOOKUP = /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|nis|corba|https?)\s*:/iu;
const OBFUSCATED_LOOKUP = /\$\{[^}]{0,60}(?:\$\{[^}]{0,40}\}|(?:lower|upper|env|sys|date|java)\s*:)[^}]{0,60}n[^}]{0,10}d[^}]{0,10}i[^}]{0,10}:/iu;
const SCANNER = /log4j[-_ ]?scan|log4shell|nuclei|interactsh|zgrab|jndi[-_ ]?exploit/iu;
// 설명 문장에서 읽는 표기
const DESC_LOOKUP = /원격 조회 구문|jndi\s*형태|jndi\s*조회|조회 구문|CVE-2021-44228/iu;
const DESC_SCANNER = /점검 도구|스캐너|scanner/iu;
const DESC_WORD = /원격 조회|jndi|로그 라이브러리|log4j/iu;
const NEGATED = /(?:표기|표식|구문|공격|삽입|주입)[^.]*(?:아닙니다|아니다|없습니다|없음)/u;

function decoded(value) {
  const text = typeof value === 'string' ? value : '';
  try { return decodeURIComponent(text.replace(/\+/gu, ' ')); } catch { return text; }
}

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
  const describedCount = description.match(/(\d+)\s*(?:건|번|회|times|requests)/iu)?.[1];
  const count = Number(data.count ?? a.count ?? describedCount ?? 0);
  const level = Number(a.rule?.level ?? a.level ?? 0);
  const headerText = flatten(data.headers ?? a.headers).map(decoded).join('\n');
  const argText = [decoded(data.url ?? a.url), ...flatten(data.args ?? a.args), ...flatten(data.full_log ?? a.full_log)].map(decoded).join('\n');
  return {
    id: String(a.id ?? a.alertId ?? ''),
    description,
    level: Number.isFinite(level) ? level : 0,
    count: Number.isFinite(count) && count >= 0 ? count : 0,
    headerText,
    argText,
  };
}

const done = (_hint, confidence, patternId, note) => ({
  action: confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record',
  confidence,
  reason: patternId ? `${patternId}: ${PATTERNS[patternId].name} - ${note} (${PATTERNS[patternId].evidence})` : `normal_request: ${note}`,
});

// 반환: { action: 'block'|'alert'|'record', confidence: 0~1, reason: string(근거 패턴 이름 포함) }
export function decide(alert) {
  const item = normalizeAlert(alert);
  if (!item.description && !item.headerText && !item.argText) return { action: 'record', confidence: 0, reason: 'invalid_alert: 내용이 없는 경보' };

  const negated = NEGATED.test(item.description);
  const inHeader = PLAIN_LOOKUP.test(item.headerText);
  const inArgs = PLAIN_LOOKUP.test(item.argText);
  const obfuscated = OBFUSCATED_LOOKUP.test(item.headerText) || OBFUSCATED_LOOKUP.test(item.argText);
  const scanner = SCANNER.test(item.headerText) || SCANNER.test(item.argText) || (!negated && DESC_SCANNER.test(item.description));
  const described = !negated && DESC_LOOKUP.test(item.description);
  const word = !negated && DESC_WORD.test(item.description);
  const strongLevel = item.level >= BLOCK_LEVEL;

  const form = inHeader ? 'remote_lookup_in_header' : inArgs ? 'remote_lookup_in_args' : obfuscated ? 'obfuscated_lookup' : null;

  // 1) 명확한 공격: 요청에 실제 조회 구문이 있고 규칙 수준이 높다 → block
  if (form && strongLevel) {
    const confidence = scanner || item.count >= BLOCK_COUNT ? 0.95 : 0.9;
    return done('block', confidence, form, `규칙 수준 ${item.level}, 조회 구문 확인${scanner ? ', 점검 도구 흔적 동반' : ''}`);
  }
  // 요청 원문이 없는 요약 경보: 설명의 조회 표기 + 반복 + 높은 규칙 수준
  if (described && strongLevel && item.count >= BLOCK_COUNT) {
    return done('block', 0.88, 'described_lookup_signal', `같은 표기 ${item.count}번 반복, 규칙 수준 ${item.level}`);
  }

  // 2) 애매함: 조회 구문이 한 번뿐이거나 규칙 수준이 낮음, 점검 도구 흔적만 있음 → alert
  if (form) return done('alert', 0.7, form, `규칙 수준 ${item.level}, 반복·근거 부족`);
  if (scanner) return done('alert', 0.6, 'vuln_scanner_trace', '점검 도구 흔적만 있고 조회 구문은 없음');
  if (described) return done('alert', 0.6, 'described_lookup_signal', `설명에 조회 표기, 반복 ${item.count}번·규칙 수준 ${item.level}로 근거 부족`);
  if (word) return done('alert', ALERT_AT, 'described_lookup_signal', '낱말만 닮음, 조회 구문 모양은 없음');

  // 3) 정상 이벤트
  return done('record', item.level <= 3 ? 0.05 : 0.1, null, '알려진 악용 형태 아님');
}
