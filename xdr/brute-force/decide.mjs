import { PATTERNS, contextFor, withOutcome } from './context.mjs';
import { extract } from './read-alerts.mjs';

export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
const STRONG_CONFIDENCE = 0.95;
const NONE_CONFIDENCE = 0.1;

const pick = (context, path) => path.split('.').reduce((obj, key) => obj?.[key], context);
const action = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

// Jev is reached through JEV_URL (https, or http on localhost). No answer in time or a bad answer returns null.
async function defaultAskJev(payload, { signal } = {}) {
  const raw = process.env.JEV_URL;
  if (!raw) return null;
  const url = new URL(raw);
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) return null;
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload), signal });
  if (!response.ok) return null;
  return (await response.json()).confidence;
}

async function ask(askJev, payload, timeoutMs) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((resolve) => { timer = setTimeout(() => { controller.abort(); resolve(null); }, timeoutMs); });
  try {
    const value = await Promise.race([Promise.resolve().then(() => askJev(payload, { signal: controller.signal })), timeout]);
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1 ? value : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// Sequential state so decide(alert) also works when alerts arrive one by one (raw Wazuh alerts or extracted rows).
const MAX_HISTORY = 5000;
const BLOCK_MEMORY_MS = 3600 * 1000;
let history = [];
let blocked = new Map();
export function resetState() { history = []; blocked = new Map(); }

function normalize(alert) {
  if (alert && alert.outcome && 'context' in alert) return { row: alert, supplied: true };
  const looksRaw = alert && typeof alert === 'object' && (alert.rule || alert.data || alert.timestamp);
  const base = looksRaw ? extract(alert, history.length) : { alertId: alert?.alertId ?? `row-${history.length + 1}`, at: alert?.at ?? null,
    srcip: alert?.srcip ?? null, account: alert?.account ?? null, level: Number.isFinite(Number(alert?.level)) ? Number(alert.level) : null,
    description: typeof alert?.description === 'string' ? alert.description : '' };
  return { row: withOutcome(base), supplied: false };
}

// alert: a raw Wazuh alert, a row from read-alerts.mjs, or an enriched row. Returns { action, confidence, reason }.
export async function decide(alert, options = {}) {
  const { row, supplied } = normalize(alert);
  let enriched = row;
  if (!supplied) {
    const seen = history.some((o) => o.alertId === row.alertId && o.at === row.at);
    enriched = { ...row, context: contextFor(history, row) };
    if (!seen) { history.push(row); if (history.length > MAX_HISTORY) history.shift(); }
  }
  const out = await judge(enriched, options);
  const ms = Number.isFinite(row.ms) ? row.ms : Date.parse(row.at);
  if (row.srcip && Number.isFinite(ms)) {
    if (out.action === 'block') blocked.set(row.srcip, ms + BLOCK_MEMORY_MS);
    else if ((blocked.get(row.srcip) ?? 0) > ms) {
      return { action: 'block', confidence: 0.9, reason: 'already_blocked: 이미 차단된 주소의 후속 경보' };
    }
  }
  return out;
}

async function judge(alert, { askJev = defaultAskJev, timeoutMs = 5000 } = {}) {
  if (alert?.outcome === 'correlated' && alert.srcip) {
    const c = PATTERNS.patterns.find((p) => p.id === 'wazuh_correlated_bruteforce');
    return alert.context?.sharedAddress
      ? { action: 'alert', confidence: 0.6, reason: `${c.id}: ${c.name} (${c.mitre.id}) - 여러 계정이 성공한 공유 주소로 보여 알림만` }
      : { action: 'block', confidence: STRONG_CONFIDENCE, reason: `${c.id}: ${c.name} 수준 ${alert.level} (${c.mitre.id})` };
  }
  if (alert?.outcome !== 'failure' || !alert.context) {
    return { action: 'record', confidence: NONE_CONFIDENCE, reason: 'no_pattern: 로그인 실패 경보가 아니거나 출발 주소가 없음' };
  }
  const hits = PATTERNS.patterns.filter((p) => p.metric).map((p) => {
    const value = pick(alert.context, p.metric);
    return { p, value, tier: value >= p.block ? 'strong' : value >= p.suspect ? 'weak' : 'none' };
  }).filter((h) => h.tier !== 'none').sort((a, b) => (b.tier === 'strong') - (a.tier === 'strong') || b.value / b.p.block - a.value / a.p.block);
  if (!hits.length) {
    return { action: 'record', confidence: NONE_CONFIDENCE, reason: 'no_pattern: 실패 횟수가 기준 미만이라 근거 패턴 없음' };
  }
  const { p, value, tier } = hits[0];
  const line = `${p.id}: ${p.name} ${value}건/${p.windowSeconds}초 (${p.mitre.id})`;
  const shared = alert.context.sharedAddress;
  if (tier === 'strong') {
    return shared
      ? { action: 'alert', confidence: 0.6, reason: `${line} - 여러 계정이 성공한 공유 주소로 보여 알림만` }
      : { action: 'block', confidence: STRONG_CONFIDENCE, reason: `${line} - 기준 초과` };
  }
  const answer = await ask(askJev, { pattern: p.id, mitre: p.mitre.id, metrics: alert.context, level: alert.level,
    description: alert.description, threshold: { suspect: p.suspect, block: p.block } }, timeoutMs);
  if (answer === null) return { action: 'alert', confidence: ALERT_AT, reason: `${line} - 애매함, Jev 응답 없음` };
  const final = shared ? Math.min(answer, 0.6) : answer;
  return { action: action(final), confidence: final, reason: `${line} - 애매함, Jev 확신도 ${answer}${shared ? ' (공유 주소라 상한 적용)' : ''}` };
}
