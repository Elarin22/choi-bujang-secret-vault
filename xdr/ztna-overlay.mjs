import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { isIP } from 'node:net';

const safeId = value => /^[A-Za-z0-9._-]{1,80}$/u.test(value ?? '') && !/sb_secret_|Bearer|eyJ/iu.test(value);
export function ruleFor(alert, result, moduleKey) {
  const time = Date.parse(alert?.timestamp);
  if (result?.action !== 'block' || result.confidence < 0.85 || !Number.isFinite(time)
      || !isIP(String(alert?.data?.srcip ?? '')) || !safeId(alert?.id)) return null;
  return {
    id: `xdr.${moduleKey}.${alert.id}`, moduleKey, sourceIp: alert.data.srcip,
    action: 'deny', confidence: result.confidence, evidenceAlertId: alert.id,
    issuedAt: new Date(time).toISOString(), expiresAt: new Date(time + 15 * 60 * 1000).toISOString(),
    reason: result.reason,
  };
}
export function activeDenial(rules, { sourceIp, sourceVerified, at }) {
  // sourceIp comes from a verified relay context, never a browser body/header.
  if (sourceVerified !== true || !isIP(String(sourceIp ?? ''))) return null;
  const now = Date.parse(at);
  if (!Number.isFinite(now)) return null;
  return rules.find(rule => rule.action === 'deny' && rule.confidence >= 0.85
    && rule.sourceIp === sourceIp && safeId(rule.evidenceAlertId)
    && Date.parse(rule.issuedAt) <= now && now < Date.parse(rule.expiresAt)) ?? null;
}
export function withXdr(baseDecide, rules) {
  return async (request, verifiedContext = {}) => {
    const matched = activeDenial(rules, { ...verifiedContext, at: request.at });
    if (matched) return { schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'xdr_blocked', ruleIds: [matched.id] };
    return baseDecide(request);
  };
}
export async function publishDecisions(root, fixture, result) {
  const folder = join(root, 'xdr');
  await mkdir(folder, { recursive: true });
  const rulesPath = join(folder, 'deny-rules.json');
  let prior = [];
  try { prior = JSON.parse(await readFile(rulesPath, 'utf8')).rules ?? []; }
  catch (error) { if (error.code !== 'ENOENT') throw new Error('기존 XDR 규칙 파일을 확인하세요.'); }
  const byId = new Map(result.decisions.map(row => [row.alertId, row]));
  const rules = fixture.alerts.map(alert => ruleFor(alert, byId.get(alert.id), fixture.moduleKey)).filter(Boolean);
  const combined = [...prior.filter(rule => rule.moduleKey !== fixture.moduleKey), ...rules];
  await writeFile(rulesPath, `${JSON.stringify({ schema: 'aleph.xdr.deny.v1', rules: combined }, null, 2)}\n`);
  // Replaying the same event does not duplicate its audit line.
  const logPath = join(folder, 'alerts.log');
  let previous = [];
  try { previous = (await readFile(logPath, 'utf8')).split('\n').filter(Boolean).map(line => JSON.parse(line)); }
  catch (error) { if (error.code !== 'ENOENT') throw new Error('기존 XDR 알림 로그를 확인하세요.'); }
  const entries = new Map(previous.map(row => [`${row.moduleKey}:${row.alertId}`, row]));
  for (const row of result.decisions.filter(row => row.action !== 'record')) {
    if (!safeId(row.alertId)) continue;
    entries.set(`${fixture.moduleKey}:${row.alertId}`, { moduleKey: fixture.moduleKey, ...row });
  }
  await writeFile(logPath, `${[...entries.values()].map(row => JSON.stringify(row)).join('\n')}\n`);
  return rules;
}
