import { readFile } from 'node:fs/promises';
import { readAlerts } from './read-alerts.mjs';
import { enrich } from './context.mjs';
import { decide, resetState } from './decide.mjs';
import { createBridge } from './bridge.mjs';
import { findRule } from './gate.mjs';

const here = (name) => new URL(name, import.meta.url);

export async function runBruteForce({ fixture, labels, allowlist, askJev, ttlSeconds } = {}) {
  const fixtureUrl = fixture ?? new URL('../fixtures/brute-force.json', import.meta.url);
  const rows = await readAlerts(fixtureUrl);
  const raw = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  const labelMap = JSON.parse(await readFile(labels ?? new URL('../fixtures/brute-force.labels.json', import.meta.url), 'utf8'));
  const list = allowlist ?? JSON.parse(await readFile(here('allowlist.json'), 'utf8')).srcips;
  resetState();
  const bridge = createBridge({ allowlist: list, ttlSeconds });
  const enriched = enrich(rows);
  const counts = { block: 0, alert: 0, record: 0 };
  const byLabel = {};
  const normalBlocked = [];
  const finals = [];
  for (const row of enriched) {
    const decision = await decide(row, askJev ? { askJev } : {});
    const final = bridge.handle(row, decision);
    counts[final.action] += 1;
    const label = labelMap[row.alertId] ?? 'unlabeled';
    byLabel[label] ??= { block: 0, alert: 0, record: 0 };
    byLabel[label][final.action] += 1;
    if (label === 'normal' && final.action === 'block') normalBlocked.push(row.alertId);
    finals.push({ row, label });
  }
  const rules = bridge.rules();
  const replay = { blocked: { normal: 0, ambiguous: 0, attack: 0 }, passed: { normal: 0, ambiguous: 0, attack: 0 } };
  for (const { row, label } of finals) {
    const hit = findRule(row.srcip, rules, Date.parse(row.at));
    replay[hit ? 'blocked' : 'passed'][label] = (replay[hit ? 'blocked' : 'passed'][label] ?? 0) + 1;
  }
  return {
    rules, logLines: bridge.logLines(),
    result: {
      schema: 'xdr.brute-force.result.v1',
      fixture: 'xdr/fixtures/brute-force.json',
      alertCount: raw.length ?? raw.alerts?.length ?? rows.length,
      extractedRows: rows.length,
      counts, byLabel, normalBlocked,
      downgradedToAlert: bridge.downgraded(),
      denyRules: rules.map((r) => ({ id: r.id, srcip: r.match.srcip, expiresAt: r.expiresAt, evidenceAlertIds: r.evidenceAlertIds })),
      replay,
      jev: askJev || process.env.JEV_URL ? 'configured' : 'not_configured',
      note: '가상 Wazuh 경보로 돌린 로컬 연습 결과입니다. 심판 판정이나 실제 차단이 아닙니다.',
    },
  };
}
