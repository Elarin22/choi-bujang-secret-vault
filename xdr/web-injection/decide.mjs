// 단일 파일 판정 모듈: 다른 파일·패키지를 불러오지 않고 파일 시스템도 쓰지 않습니다.
// 입력: Wazuh 원본 경보, 또는 {id, sourceIp, level, count, description} 요약.
// 근거: MITRE ATT&CK T1190 (외부 공개 앱 악용). 기준 숫자는 학습용 가정입니다.
// 요청 주소(url)는 패턴 확인에만 쓰고 reason·Jev 요청에는 넣지 않습니다.

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const BLOCK_LEVEL = 10;   // 규칙 수준 이 값 이상 + 반복이면 명확한 공격
const BLOCK_COUNT = 5;    // 같은 주소에서 이 횟수 이상 반복
const RAW_WINDOW_MS = 300 * 1000;
const MAX_HISTORY = 5000;

// 설명 문장에서 찾는 표기 (요약 경보)
const DESC_KINDS = [
  ['repeated_sql_syntax', /SQL.*(?:구문|표식|표기|주입)|데이터베이스 조회|sql injection|union\s+select/iu],
  ['repeated_script_injection', /스크립트.*(?:삽입|표식|표기|주입)|script injection|cross.site scripting|<script\b/iu],
  ['repeated_path_traversal', /경로.*(?:거슬러|이탈|탐색)|path traversal|(?:\.\.\/){2}/iu],
  ['repeated_command_separator', /명령 구분자|command injection/iu],
];
// 요청 주소·인자 안의 실제 모양 (원본 경보). 주소는 한 번 풀어서(디코딩) 본다.
const URL_KINDS = [
  ['repeated_sql_syntax', /union\s+select|\bor\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table|\bselect\b.+\bfrom\b|sleep\s*\(/iu],
  ['repeated_script_injection', /<\s*script|javascript:|\bonerror\s*=|\bonload\s*=/iu],
  ['repeated_path_traversal', /(?:\.\.[/\\]){2,}/u],
  ['repeated_command_separator', /(?:;|\||&&|`|\$\()\s*(?:cat|ls|id|whoami|curl|wget|sh|bash|nc)\b/iu],
];
// "삽입 표식은 아닙니다", "공격 표기는 없습니다" 처럼 부정하는 문장은 공격 표기로 보지 않는다.
const NEGATED = /(?:표기|표식|구문|공격|삽입|주입)[^.]*(?:아닙니다|아니다|없습니다|없음)/u;
// 애매한 문장: 낱말만 있거나 한 번뿐이라 사람이 확인할 만한 것
const AMBIGUOUS = /따옴표|select|스크립트|경로.*up|SQL|이상한 검색|주입처럼|구분 문자|(?:요청 주소|URL|URI).*(?:평소보다\s*(?:길|깁)|비정상.*(?:길|깁))/iu;

let history = [];

function toMs(timestamp) {
  if (typeof timestamp !== 'string') return Number.NaN;
  return Date.parse(timestamp.replace(/([+-]\d{2})(\d{2})$/u, '$1:$2'));
}

function decoded(value) {
  const text = typeof value === 'string' ? value : '';
  try { return decodeURIComponent(text.replace(/\+/gu, ' ')); } catch { return text; }
}

function normalizeAlert(alert) {
  const a = alert && typeof alert === 'object' ? alert : {};
  const data = a.data && typeof a.data === 'object' ? a.data : {};
  const description = String(a.rule?.description ?? a.description ?? '');
  const describedCount = description.match(/(\d+)\s*(?:건|번|회|times|requests)/iu)?.[1];
  const count = Number(data.count ?? a.count ?? describedCount ?? 0);
  const level = Number(a.rule?.level ?? a.level ?? 0);
  return {
    id: String(a.id ?? a.alertId ?? ''),
    description,
    level: Number.isFinite(level) ? level : 0,
    count: Number.isFinite(count) && count >= 0 ? count : 0,
    sourceIp: String(data.srcip ?? data.src_ip ?? a.sourceIp ?? a.srcip ?? ''),
    url: decoded(data.url ?? a.url),
    ms: toMs(a.timestamp ?? a.at),
  };
}

const firstKind = (kinds, text) => kinds.find(([, pattern]) => pattern.test(text))?.[0] ?? null;

async function askJev(item, timeoutMs) {
  const endpoint = typeof process !== 'undefined' ? (process.env?.JEV_URL ?? process.env?.JEV_DECISION_URL) : undefined;
  if (!endpoint) return null;
  try {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) return null;
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'web_injection_review', alertId: item.id, level: item.level, count: item.count, pattern: item.kind ?? null }),
      signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) return null;
    const verdict = (await response.json())?.confidence;
    return typeof verdict === 'number' && Number.isFinite(verdict) && verdict >= 0 && verdict <= 1 ? verdict : null;
  } catch {
    return null;
  }
}

// 애매한 경보만 Jev 에게 확신도를 묻는다. 응답이 없거나 이상하면 alert.
async function ambiguous(item, reason, { ask, timeoutMs }) {
  let confidence = null;
  try { confidence = await Promise.race([Promise.resolve().then(() => ask(item, timeoutMs)), new Promise((r) => setTimeout(() => r(null), timeoutMs))]); } catch { confidence = null; }
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    return { action: 'alert', confidence: ALERT_AT, reason: `${reason} - 애매함, Jev 응답 없음` };
  }
  const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
  return { action, confidence, reason: `${reason} - 애매함, Jev 확신도 ${confidence}` };
}

// 반환: { action: 'block'|'alert'|'record', confidence: 0~1, reason: string(근거 패턴 이름 포함) }
export async function decide(alert, options = {}) {
  const opts = { ask: options.askJev ?? askJev, timeoutMs: options.timeoutMs ?? 3000 };
  const item = normalizeAlert(alert);
  if (!item.description) return { action: 'record', confidence: 0, reason: 'invalid_alert: 설명이 없는 경보' };

  const negated = NEGATED.test(item.description);
  const descKind = negated ? null : firstKind(DESC_KINDS, item.description);
  const urlKind = firstKind(URL_KINDS, item.url);
  let count = item.count;

  // 횟수 요약이 없는 원본 경보는 같은 주소의 앞선 주입 시도를 5분 창에서 기억해 센다.
  if (urlKind && item.count === 0 && item.sourceIp && Number.isFinite(item.ms)) {
    if (!history.some((o) => o.id === item.id && o.ms === item.ms)) {
      history.push({ id: item.id, ms: item.ms, srcip: item.sourceIp, kind: urlKind });
      if (history.length > MAX_HISTORY) history.shift();
    }
    count = history.filter((o) => o.srcip === item.sourceIp && o.kind === urlKind && o.ms <= item.ms && item.ms - o.ms <= RAW_WINDOW_MS).length;
  }

  // 1) 정상 이벤트: 낮은 규칙 수준에 한 번뿐이고 공격 표기가 없으면 기록만
  if (item.level <= 3 && count <= 1 && !urlKind) return { action: 'record', confidence: 0.05, reason: 'normal_web_request: 낮은 수준의 정상 요청' };

  // 2) 명확한 공격: 공격 표기 + 같은 주소의 반복 + 높은 규칙 수준 → block
  const kind = descKind ?? urlKind;
  if (kind && count >= BLOCK_COUNT && (item.level >= BLOCK_LEVEL || (urlKind && !descKind))) {
    return { action: 'block', confidence: 0.9, reason: `${kind}: 같은 주소에서 ${count}번 반복된 주입 표기 (T1190)` };
  }

  // 3) 애매함: 공격 표기가 한두 번뿐이거나 낱말만 닮은 것 → Jev, 응답 없으면 alert
  if (kind || AMBIGUOUS.test(item.description)) {
    return ambiguous({ ...item, count, kind }, `ambiguous_web_input: ${kind ?? '주입을 닮은 낱말'}, 반복·근거 부족`, opts);
  }
  return { action: 'record', confidence: 0.1, reason: 'normal_web_request: 주입 패턴 아님' };
}
