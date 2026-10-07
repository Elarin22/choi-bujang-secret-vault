import { readFileSync } from 'node:fs';

export const PATTERNS = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const byId = (id) => PATTERNS.patterns.find((p) => p.id === id);
const windowMs = (id) => byId(id).windowSeconds * 1000;
const CORRELATION = byId('wazuh_correlated_bruteforce');

export function classify(description) {
  const text = String(description).toLowerCase();
  if (/fail|invalid user|denied/u.test(text)) return 'failure';
  if (/success|accepted/u.test(text)) return 'success';
  return 'other';
}

// A Wazuh correlation alert already summarizes earlier failures, so it is not counted as one more failure.
export function classifyRow(row) {
  if (row.level >= CORRELATION.minLevel && new RegExp(CORRELATION.descriptionPattern, 'iu').test(row.description)) return 'correlated';
  return classify(row.description);
}

// prior: rows seen before (outcome and ms already set). Counts only prior rows plus the row itself.
export function contextFor(prior, row) {
  if (!['failure', 'correlated'].includes(row.outcome) || !row.srcip || !Number.isFinite(row.ms)) return null;
  const before = prior.filter((o) => o.srcip === row.srcip && Number.isFinite(o.ms) && o.ms <= row.ms);
  const failures = [...before, row].filter((o) => o.outcome === 'failure');
  const rapidMs = windowMs('rapid_failed_logins');
  const sprayMs = windowMs('password_spraying');
  const sameAccount = failures.filter((o) => o.account === row.account && row.ms - o.ms <= rapidMs);
  const spray = failures.filter((o) => row.ms - o.ms <= sprayMs);
  const burstMs = windowMs('rapid_burst');
  const fastMs = windowMs('fast_spraying');
  const burst = failures.filter((o) => o.account === row.account && row.ms - o.ms <= burstMs);
  const fast = failures.filter((o) => row.ms - o.ms <= fastMs);
  const successAccounts = new Set(before.filter((o) => o.outcome === 'success' && o.account).map((o) => o.account));
  return {
    rapid: { windowSeconds: rapidMs / 1000, failuresSameAccount: sameAccount.length },
    spray: { windowSeconds: sprayMs / 1000, distinctAccounts: new Set(spray.map((o) => o.account)).size,
      failuresFromSource: spray.length },
    burst: { windowSeconds: burstMs / 1000, failuresSameAccount: burst.length },
    fastSpray: { windowSeconds: fastMs / 1000, distinctAccounts: new Set(fast.map((o) => o.account)).size },
    sharedAddress: successAccounts.size >= PATTERNS.guards.sharedAddressSuccessAccounts,
  };
}

export function withOutcome(row) {
  return { ...row, outcome: classifyRow(row), ms: row.at ? Date.parse(row.at) : Number.POSITIVE_INFINITY };
}

export function enrich(rows) {
  const items = rows.map((row, index) => ({ ...withOutcome(row), index }));
  items.sort((a, b) => (a.ms - b.ms) || (a.index - b.index));
  return items.map((item, k) => {
    const { index, ms, ...row } = item;
    return { ...row, context: contextFor(items.slice(0, k), item) };
  });
}
