import { readFileSync } from 'node:fs';

export const PATTERNS = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const windowOf = (id) => PATTERNS.patterns.find((p) => p.id === id).windowSeconds * 1000;

export function classify(description) {
  const text = String(description).toLowerCase();
  if (/fail|invalid user|denied/u.test(text)) return 'failure';
  if (/success|accepted/u.test(text)) return 'success';
  return 'other';
}

// Adds, for every login failure, how many failures the same address made inside each pattern window.
export function enrich(rows) {
  const items = rows.map((row, index) => ({
    ...row, index, outcome: classify(row.description),
    ms: row.at ? Date.parse(row.at) : Number.POSITIVE_INFINITY,
  }));
  items.sort((a, b) => (a.ms - b.ms) || (a.index - b.index));
  const rapidMs = windowOf('rapid_failed_logins');
  const sprayMs = windowOf('password_spraying');
  return items.map((item, k) => {
    const { index, ms, ...row } = item;
    if (item.outcome !== 'failure' || !item.srcip || !Number.isFinite(ms)) return { ...row, context: null };
    const before = items.slice(0, k + 1).filter((o) => o.srcip === item.srcip && Number.isFinite(o.ms));
    const failures = before.filter((o) => o.outcome === 'failure');
    const sameAccount = failures.filter((o) => o.account === item.account && ms - o.ms <= rapidMs);
    const spray = failures.filter((o) => ms - o.ms <= sprayMs);
    const successAccounts = new Set(before.filter((o) => o.outcome === 'success' && o.account).map((o) => o.account));
    return { ...row, context: {
      rapid: { windowSeconds: rapidMs / 1000, failuresSameAccount: sameAccount.length },
      spray: { windowSeconds: sprayMs / 1000, distinctAccounts: new Set(spray.map((o) => o.account)).size,
        failuresFromSource: spray.length },
      sharedAddress: successAccounts.size >= PATTERNS.guards.sharedAddressSuccessAccounts,
    } };
  });
}
