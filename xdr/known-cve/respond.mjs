import { publishDecisions, withXdr } from '../ztna-overlay.mjs';

// The existing base policy remains the final authority for all unmatched events.
export function connectDecider(baseDecide, rules) {
  return withXdr(baseDecide, rules.filter(rule => rule.moduleKey === 'known-cve'));
}
export async function respond(root, fixture, result) {
  if (fixture?.moduleKey !== 'known-cve' || result?.moduleKey !== 'known-cve'
      || !Array.isArray(fixture.alerts) || !Array.isArray(result.decisions)
      || result.decisions.length !== fixture.alerts.length) throw new Error('known-cve 응답 형식을 확인하세요.');
  const expected = new Set(fixture.alerts.map(alert => alert.id));
  if (expected.size !== fixture.alerts.length) throw new Error('중복 경보 번호를 확인하세요.');
  const decisions = result.decisions.map(row => {
    if (!expected.delete(row.alertId) || !Number.isFinite(row.confidence)
        || row.confidence < 0 || row.confidence > 1
        || row.action !== (row.confidence >= 0.85 ? 'block' : row.confidence >= 0.5 ? 'alert' : 'record')
        || typeof row.reason !== 'string'
        || !/^kc_(remote_lookup|cve_reference|scanner_trace|unconfirmed|normal|invalid):/u.test(row.reason)) {
      throw new Error('known-cve 판정 결과를 확인하세요.');
    }
    // Audit only the static pattern name; no original URL, account or secret.
    return { alertId: row.alertId, action: row.action, confidence: row.confidence,
      reason: row.reason.split(':', 1)[0] };
  });
  return publishDecisions(root, fixture, { ...result, decisions });
}
