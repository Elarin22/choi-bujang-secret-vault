import { readFileSync } from 'node:fs';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { planPolicyRestore } from './policy-recovery.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

// 고정된 가상 입력으로만 판정기·탐지 규칙을 실행한다. 사용자가 보낸 값은 사례 이름(고정 목록과 비교)뿐이고 코드로 실행하지 않는다.
// 실제 세션·메모·기기 상태는 읽거나 바꾸지 않는다. ready 는 "가상 조건에서 기대한 결과가 나왔다"는 뜻이며 실제 기기의 승인 상태가 아니다.
// source 는 학생 작업, engine 은 제공 엔진이다. 엔진이 그 판정을 실제 요청에서 집행했는지는 이 저장소에서 확인하지 못하므로 engineEnforced 는 not_run 이다.
const ENGINE = 'ALEPH SDP engine';
const SOURCE_DECIDER = '학생 판정기(src/decider.mjs)';
const SOURCE_DETECT = '학생 탐지 규칙(src/detect.mjs)';
const SOURCE_BACKUP = '학생 안전 정책 사본(backups/safe-policy.json)';

const withRoute = (route, method, path) => ({ ...fixtureRequests().normal, route, method, path });

export const RULE_CASES = Object.freeze({
  's06-unregistered': [() => ({ ...fixtureRequests().normal, deviceRegistered: false }), 'deny'],
  's07-compound': [() => fixtureRequests().suspicious, 'step_up'],
  's08-unknown-route': [() => withRoute('GET /__unknown__', 'GET', '/__unknown__'), 'deny'],
  's08-all-notes': [() => withRoute('GET /api/notes', 'GET', '/api/notes'), 'deny'],
  's08-write-notice': [() => withRoute('POST /api/notices', 'POST', '/api/notices'), 'deny'],
});

const base = (source) => ({ source, engine: ENGINE, engineEnforced: 'not_run' });

export async function runRuleCheck(caseId) {
  if (typeof caseId !== 'string') return null;
  if (Object.hasOwn(RULE_CASES, caseId)) {
    const [build, expected] = RULE_CASES[caseId];
    const result = await decide(build());
    return { ready: result.decision === expected, decision: result.decision, reasonCode: result.reasonCode, ruleIds: result.ruleIds, ...base(SOURCE_DECIDER) };
  }
  if (caseId === 's09-burst-read') {
    const start = Date.now();
    const events = Array.from({ length: 121 }, (_, i) => ({ at: new Date(start + i * 2000).toISOString(), method: 'GET', identity: { sub: 'check_user' } }));
    const result = detect(events);
    return { ready: result.action === 'propose_revocation', action: result.action, reasonCode: result.reasonCode ?? null, ...base(SOURCE_DETECT) };
  }
  if (caseId === 's10-policy-verified') {
    try {
      const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
      const backup = JSON.parse(readFileSync(new URL('../backups/safe-policy.json', import.meta.url), 'utf8'));
      const plan = planPolicyRestore({ projectId: config.repoUrl, policyRevision: backup.policyRevision, allowedRoutes: config.allowedRoutes, audit: [] }, backup);
      return { ready: plan.service === 'notes', restoreVersion: plan.backupRevision, ...base(SOURCE_BACKUP) };
    } catch {
      return { ready: false, restoreVersion: null, ...base(SOURCE_BACKUP) };
    }
  }
  return null;
}
