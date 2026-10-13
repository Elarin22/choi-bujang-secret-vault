// 12단계 제작 1: 탈환 작전실이 읽는 서버 요약입니다.
// 메모 본문·토큰·확인 코드·키는 담지 않고, 개수·버전·상태 이름만 돌려줍니다.
// 상태 이름(status)은 네 가지뿐이며, 화면은 이 값을 그대로 보여 줍니다(성공 문구를 따로 만들지 않습니다).
//   confirmed_now  : 이 요청을 처리하면서 서버가 실제 파일·엔진 응답으로 방금 확인한 값
//   declared_code  : 코드에 적힌 값을 읽었을 뿐, 이번에 실행해서 시험하지 않은 값
//   not_connected  : 연결이 없어 확인하지 못한 값(승인 확인이 열리지 않은 것으로 취급)
//   not_run        : 실행하지 않았거나 실행할 수단이 없는 값
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { deviceService } from './device.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import { BURST_LIMIT, BURST_WINDOW_MS } from '../src/detect.mjs';
import { planPolicyRestore, verifyPolicyBackup } from '../src/policy-recovery.mjs';

export const SUMMARY_SCHEMA = 'vault.ops.summary.v1';

const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));

// 기본 입력: 배포에 포함된 설정 파일·정책 사본·감사 기록 줄 수만 읽습니다(내용은 내보내지 않습니다).
export function loadInputs(root = process.cwd()) {
  const config = readJson(join(root, 'aleph.config.json'));
  const backupPath = join(root, 'backups', 'safe-policy.json');
  const auditPath = join(root, 'backups', 'policy-audit.jsonl');
  const backup = existsSync(backupPath) ? readJson(backupPath) : null;
  const auditEntries = existsSync(auditPath) ? readFileSync(auditPath, 'utf8').split(/\r?\n/u).filter(Boolean).length : 0;
  return { config, backup, auditEntries };
}

function deviceSection(state) {
  const connected = state?.connected === true && state?.authority === 'ALEPH SDP engine';
  return {
    status: connected ? 'confirmed_now' : 'not_connected',
    approval: typeof state?.approval === 'string' ? state.approval : 'unavailable',
    authority: typeof state?.authority === 'string' ? state.authority : null,
    requestId: typeof state?.requestId === 'string' ? state.requestId : null,
    checkedAt: typeof state?.checkedAt === 'string' ? state.checkedAt : null,
  };
}

function recoverySection({ config, backup, auditEntries }) {
  const base = { restoreRoute: typeof config.restoreRoute === 'string' ? config.restoreRoute : null,
    noteRestoreRun: { status: 'not_run' } };
  if (!backup) return { ...base, status: 'not_run', reason: 'policy_backup_missing' };
  try {
    const state = { projectId: config.repoUrl, policyRevision: config.policyRevision ?? 1,
      allowedRoutes: config.allowedRoutes ?? [], audit: new Array(auditEntries).fill(null) };
    const safe = verifyPolicyBackup(backup, state.projectId);
    const plan = planPolicyRestore(state, backup);
    return { ...base, status: 'confirmed_now', backupRevision: safe.policyRevision, currentRevision: plan.expectedRevision,
      backupRoutes: plan.after.length, addedRoutes: plan.added.length, removedRoutes: plan.removed.length,
      policyMatchesBackup: plan.unchanged, preservedOtherRoutes: plan.preservedOtherRoutes.length, auditEntries };
  } catch (error) {
    // 사본이 깨졌거나 프로젝트가 다르면 복원은 중단되는 것이 맞습니다. 이유 코드만 알립니다.
    return { ...base, status: 'confirmed_now', backupRevision: null, policyMatchesBackup: false,
      reason: error instanceof Error && /^invalid_/u.test(error.message) ? error.message : 'policy_backup_unreadable' };
  }
}

export function buildOpsSummary({ config, backup, auditEntries = 0, device, now = new Date() }) {
  return {
    schema: SUMMARY_SCHEMA,
    generatedAt: now.toISOString(),
    step: Number.isInteger(config?.step) ? config.step : null,
    device: deviceSection(device),
    decider: { status: 'declared_code', ruleCount: RULE_IDS.length, ruleIds: [...RULE_IDS],
      allowedRoutes: Array.isArray(config?.allowedRoutes) ? config.allowedRoutes.length : 0,
      judgeVerdict: { status: 'not_run' } },
    detection: { status: 'declared_code', rule: 'burst_read', limit: BURST_LIMIT, windowMinutes: BURST_WINDOW_MS / 60000,
      events: { status: 'not_run', count: null } },
    revocation: { status: 'not_run', proposalOnly: true },
    recovery: recoverySection({ config, backup, auditEntries }),
  };
}

const headers = (res) => { res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); };

export function createOpsHandler({ service = deviceService, load = loadInputs, now = () => new Date() } = {}) {
  return async (req, res) => {
    headers(res);
    if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); return res.status(405).json({ error: '허용되지 않는 요청 방식입니다.' }); }
    let inputs;
    try { inputs = load(); } catch { return res.status(500).json({ error: '작전실 요약을 만들지 못했습니다.' }); }
    const device = await service.status(req, null);
    return res.status(200).json(buildOpsSummary({ ...inputs, device, now: now() }));
  };
}