import { readFile, writeFile } from 'node:fs/promises';
import { withXdr } from '../xdr/ztna-overlay.mjs';
const { rules } = JSON.parse(await readFile(new URL('../xdr/deny-rules.json', import.meta.url), 'utf8'));
// Allowing baseline is a test double; the actual starter still denies by default.
const baseline = async request => ({ schema: 'aleph.decision.v1', requestId: request.requestId,
  decision: 'allow', reasonCode: 'test_baseline', ruleIds: [] });
const gated = withXdr(baseline, rules);
const counts = { attackDenied: 0, normalDenied: 0, ambiguousDenied: 0, expiredDenied: 0 };
for (const moduleKey of ['brute-force', 'web-injection']) {
  const fixture = JSON.parse(await readFile(new URL(`../xdr/fixtures/${moduleKey}.json`, import.meta.url), 'utf8'));
  const result = JSON.parse(await readFile(new URL(`../xdr/${moduleKey}/result.json`, import.meta.url), 'utf8'));
  for (const row of result.decisions) {
    const alert = fixture.alerts.find(item => item.id === row.alertId);
    const at = new Date(Date.parse(alert.timestamp) + 1000).toISOString();
    const request = { requestId: row.alertId, at };
    const outcome = await gated(request, { sourceIp: alert.data.srcip, sourceVerified: true });
    if (row.action === 'block' && outcome.decision === 'deny') counts.attackDenied++;
    if (row.action === 'alert' && outcome.decision === 'deny') counts.ambiguousDenied++;
    if (row.action === 'record' && outcome.decision === 'deny') counts.normalDenied++;
    const allExpired = Math.max(Date.parse(at) + 16 * 60000,
      ...rules.filter(rule => rule.sourceIp === alert.data.srcip).map(rule => Date.parse(rule.expiresAt))) + 1000;
    const expired = await gated({ ...request, at: new Date(allExpired).toISOString() },
      { sourceIp: alert.data.srcip, sourceVerified: true });
    if (expired.decision === 'deny') counts.expiredDenied++;
  }
}
await writeFile(new URL('../xdr/replay-result.json', import.meta.url), `${JSON.stringify({ simulation: true, counts }, null, 2)}\n`);
console.log(JSON.stringify({ simulation: true, counts }));
if (counts.normalDenied || counts.ambiguousDenied || counts.expiredDenied) process.exitCode = 1;
