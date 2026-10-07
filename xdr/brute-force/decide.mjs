// 단일 파일 판정 모듈: 다른 파일·패키지를 불러오지 않고 파일 시스템도 쓰지 않습니다.
// 입력: Wazuh 원본 경보, 또는 {id, sourceIp, level, count, accounts, description} 요약.
// 근거: MITRE ATT&CK T1110 (Brute Force). 기준 숫자는 학습용 가정이며 MITRE가 정한 값이 아닙니다.

const FAILURE = /fail|invalid user|denied|실패/iu;
const SUCCESS = /success|accepted|성공/iu;
const SPRAY_TEXT = /같은 비밀번호|same password|password spray/iu;
const MANY_ACCOUNTS_TEXT = /여러 계정|multiple accounts/iu;
const CORRELATED = /brute force|multiple authentication failures|무차별/iu;

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const STRONG = 0.95;

// 요약 경보용 기준 (count 와 규칙 수준이 들어 있는 경보)
const RAPID_MIN_LEVEL = 10;
const RAPID_MIN_COUNT = 10;
const SPRAY_MIN_ACCOUNTS = 5;

// 한 줄씩 들어오는 원본 경보용 기준 (같은 주소의 앞선 경보를 기억해서 셈)
const WINDOWS = {
  rapid_burst: { metric: 'burst', sec: 15, suspect: 3, block: 3, name: '같은 주소·같은 계정 짧은 시간 폭주 실패', mitre: 'T1110.001' },
  fast_spraying: { metric: 'fastSpray', sec: 30, suspect: 3, block: 3, name: '한 주소에서 짧은 시간에 여러 계정 로그인 실패', mitre: 'T1110.003' },
  rapid_failed_logins: { metric: 'rapid', sec: 120, suspect: 5, block: 7, name: '같은 주소·같은 계정 로그인 실패 연속', mitre: 'T1110.001' },
  password_spraying: { metric: 'spray', sec: 300, suspect: 4, block: 5, name: '한 주소에서 여러 계정에 로그인 실패', mitre: 'T1110.003' },
};
const SHARED_ADDRESS_SUCCESS_ACCOUNTS = 3;
const MAX_HISTORY = 5000;
const BLOCK_MEMORY_MS = 3600 * 1000;

let history = [];
let blocked = new Map();

function toMs(timestamp) {
  if (typeof timestamp !== 'string') return Number.NaN;
  return Date.parse(timestamp.replace(/([+-]\d{2})(\d{2})$/u, '$1:$2'));
}

function normalizeAlert(alert) {
  const a = alert && typeof alert === 'object' ? alert : {};
  const data = a.data && typeof a.data === 'object' ? a.data : {};
  const description = String(a.rule?.description ?? a.description ?? '');
  const describedCount = description.match(/(\d+)\s*(?:건|번|회|failures|attempts)/iu)?.[1];
  const count = Number(data.count ?? a.count ?? describedCount ?? 0);
  const level = Number(a.rule?.level ?? a.level ?? 0);
  const accounts = data.accounts ?? a.accounts;
  const listed = Array.isArray(accounts) ? new Set(accounts).size
    : typeof accounts === 'string' ? new Set(accounts.split(',').map((s) => s.trim()).filter(Boolean)).size : 0;
  const described = Number(description.match(/계정\s*(\d+)\s*개/u)?.[1] ?? 0);
  const account = data.dstuser ?? data.srcuser ?? data.user ?? a.account ?? null;
  return {
    id: String(a.id ?? a.alertId ?? ''),
    description,
    level: Number.isFinite(level) ? level : 0,
    count: Number.isFinite(count) && count >= 0 ? count : 0,
    sourceIp: String(data.srcip ?? data.src_ip ?? a.sourceIp ?? a.srcip ?? ''),
    account: typeof account === 'string' && account ? account.slice(0, 64) : null,
    accountCount: Math.max(listed, Number.isFinite(described) ? described : 0),
    ms: toMs(a.timestamp ?? a.at),
  };
}

function classify(item) {
  if (item.level >= 10 && CORRELATED.test(item.description) && FAILURE.test(item.description)) return 'correlated';
  if (FAILURE.test(item.description)) return 'failure';
  if (SUCCESS.test(item.description)) return 'success';
  return 'other';
}

function metrics(item, outcome) {
  const failures = [...history.filter((o) => o.srcip === item.sourceIp && o.ms <= item.ms), { ...item, srcip: item.sourceIp, outcome }]
    .filter((o) => o.outcome === 'failure');
  const within = (sec, sameAccount) => failures.filter((o) => item.ms - o.ms <= sec * 1000
    && (!sameAccount || o.account === item.account));
  const out = {};
  for (const w of Object.values(WINDOWS)) {
    const rows = within(w.sec, w.metric === 'rapid' || w.metric === 'burst');
    out[w.metric] = w.metric === 'spray' || w.metric === 'fastSpray' ? new Set(rows.map((o) => o.account)).size : rows.length;
  }
  const accountsWithSuccess = new Set(history.filter((o) => o.srcip === item.sourceIp && o.outcome === 'success' && o.account).map((o) => o.account));
  out.shared = accountsWithSuccess.size >= SHARED_ADDRESS_SUCCESS_ACCOUNTS;
  return out;
}

async function askJev(summary, timeoutMs) {
  const endpoint = typeof process !== 'undefined' ? (process.env?.JEV_URL ?? process.env?.JEV_DECISION_URL) : undefined;
  if (!endpoint) return null;
  try {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) return null;
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'brute_force_review', alertId: summary.id, level: summary.level,
        failureCount: summary.count, pattern: summary.pattern ?? null }),
      signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) return null;
    const verdict = (await response.json())?.confidence;
    return typeof verdict === 'number' && Number.isFinite(verdict) && verdict >= 0 && verdict <= 1 ? verdict : null;
  } catch {
    return null;
  }
}

async function ambiguous(item, reason, { ask, timeoutMs }) {
  let confidence = null;
  try { confidence = await Promise.race([Promise.resolve().then(() => ask(item, timeoutMs)), new Promise((r) => setTimeout(() => r(null), timeoutMs))]); } catch { confidence = null; }
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    return { action: 'alert', confidence: ALERT_AT, reason: `${reason} - 애매함, Jev 응답 없음` };
  }
  const action = confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record';
  return { action, confidence, reason: `${reason} - 애매함, Jev 확신도 ${confidence}` };
}

// 반환: { action: 'block'|'alert'|'record', confidence: 0~1, reason: string }
export async function decide(alert, options = {}) {
  const opts = { ask: options.askJev ?? askJev, timeoutMs: options.timeoutMs ?? 3000 };
  const item = normalizeAlert(alert);
  if (!item.description) return { action: 'record', confidence: 0, reason: 'invalid_alert: 설명이 없는 경보' };

  // 한 줄씩 들어오는 원본 경보(횟수 요약이 없는 경보)는 같은 주소의 앞선 경보를 기억해 둔다.
  const sequential = item.count === 0 && item.accountCount === 0 && Boolean(item.sourceIp) && Number.isFinite(item.ms);
  const outcome = classify(item);
  let ctx = null;
  if (sequential) {
    const seen = history.some((o) => o.id === item.id && o.ms === item.ms);
    if (outcome === 'failure') ctx = metrics(item, outcome);
    if (!seen) {
      history.push({ id: item.id, ms: item.ms, srcip: item.sourceIp, account: item.account, outcome });
      if (history.length > MAX_HISTORY) history.shift();
    }
  }

  // 1) 정상 이벤트: 규칙 수준이 낮고 실패가 많지 않으면 기록만
  if (item.level <= 3 && item.count <= 1) return { action: 'record', confidence: 0.05, reason: 'normal_login_event: 낮은 수준의 정상 이벤트' };

  // 2) 요약 경보의 명확한 공격 → 차단
  const rapid = item.level >= RAPID_MIN_LEVEL && item.count >= RAPID_MIN_COUNT && FAILURE.test(item.description);
  const spray = SPRAY_TEXT.test(item.description);
  const manyAccounts = item.level >= RAPID_MIN_LEVEL && (spray || FAILURE.test(item.description))
    && (item.accountCount >= SPRAY_MIN_ACCOUNTS || (spray && MANY_ACCOUNTS_TEXT.test(item.description)));
  if (rapid || manyAccounts) {
    const reason = rapid ? 'same_source_rapid_failures: 같은 주소의 짧은 시간 로그인 실패 폭주 (T1110.001)'
      : 'same_password_many_accounts: 한 주소가 여러 계정에 같은 비밀번호 대입 (T1110.003)';
    return { action: 'block', confidence: rapid && manyAccounts ? 0.98 : 0.9, reason };
  }

  // 3) 한 줄씩 들어온 원본 경보: Wazuh 상관 경보, 이미 차단한 주소, 기억해 둔 실패 횟수
  if (sequential) {
    const ms = item.ms;
    if (outcome === 'correlated') {
      const shared = metrics(item, outcome).shared;
      if (shared) return { action: 'alert', confidence: 0.6, reason: 'wazuh_correlated_bruteforce: 여러 계정이 성공한 공유 주소로 보여 알림만' };
      blocked.set(item.sourceIp, ms + BLOCK_MEMORY_MS);
      return { action: 'block', confidence: STRONG, reason: `wazuh_correlated_bruteforce: Wazuh 상관 규칙 수준 ${item.level} (T1110)` };
    }
    if (outcome === 'failure' && ctx) {
      const hits = Object.entries(WINDOWS).map(([id, w]) => {
        const value = ctx[w.metric];
        return { id, w, value, tier: value >= w.block ? 'strong' : value >= w.suspect ? 'weak' : 'none' };
      }).filter((h) => h.tier !== 'none')
        .sort((x, y) => (y.tier === 'strong') - (x.tier === 'strong') || y.value / y.w.block - x.value / x.w.block);
      if (hits.length) {
        const { id, w, value, tier } = hits[0];
        const line = `${id}: ${w.name} ${value}건/${w.sec}초 (${w.mitre})`;
        if (tier === 'strong') {
          if (ctx.shared) return { action: 'alert', confidence: 0.6, reason: `${line} - 여러 계정이 성공한 공유 주소로 보여 알림만` };
          blocked.set(item.sourceIp, ms + BLOCK_MEMORY_MS);
          return { action: 'block', confidence: STRONG, reason: `${line} - 기준 초과` };
        }
        const verdict = await ambiguous({ ...item, pattern: id }, line, opts);
        if (verdict.action === 'block' && ctx.shared) return { action: 'alert', confidence: 0.6, reason: `${verdict.reason} (공유 주소라 상한 적용)` };
        if (verdict.action === 'block') blocked.set(item.sourceIp, ms + BLOCK_MEMORY_MS);
        return verdict;
      }
    }
    if ((blocked.get(item.sourceIp) ?? 0) > ms && outcome !== 'success') {
      return { action: 'block', confidence: 0.9, reason: 'already_blocked: 이미 차단된 주소의 후속 경보' };
    }
    return { action: 'record', confidence: 0.1, reason: 'no_pattern: 실패 횟수가 기준 미만이라 근거 패턴 없음' };
  }

  // 4) 요약 경보 중 기준에는 못 미치지만 로그인 실패인 것 → 애매함 (Jev, 응답 없으면 alert)
  if (FAILURE.test(item.description)) return ambiguous(item, 'ambiguous_login_failures: 기준 미만의 로그인 실패', opts);
  return { action: 'record', confidence: 0.1, reason: 'normal_login_event: 로그인 실패 패턴 아님' };
}
