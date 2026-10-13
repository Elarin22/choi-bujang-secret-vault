// 10단계 정책 복원 도구. 기본은 미리보기(아무것도 쓰지 않음)이고, --apply <확인코드>를 줄 때만 시험 정책 파일을 고칩니다.
//   npm run policy:diff                      복원할 버전과 바뀔 항목 보기
//   npm run policy:restore -- --apply <코드>   미리보기에서 나온 확인 코드로 되돌리기
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyPolicyRestore, planPolicyRestore } from '../src/policy-recovery.mjs';

const root = resolve(import.meta.dirname, '..');
const configPath = join(root, 'aleph.config.json');
const backupPath = join(root, 'backups', 'safe-policy.json');
const auditPath = join(root, 'backups', 'policy-audit.jsonl');

export function loadState() {
  const raw = readFileSync(configPath, 'utf8');
  const config = JSON.parse(raw);
  const audit = existsSync(auditPath) ? readFileSync(auditPath, 'utf8').split(/\r?\n/u).filter(Boolean).map((line) => JSON.parse(line)) : [];
  return { raw, config, state: { projectId: config.repoUrl, policyRevision: config.policyRevision ?? 1, allowedRoutes: config.allowedRoutes ?? [], audit } };
}

export function loadBackup() {
  // 사본이 없거나 읽을 수 없으면 여기서 중단합니다.
  if (!existsSync(backupPath)) throw new Error('안전 정책 사본(backups/safe-policy.json)이 없어 중단합니다.');
  return JSON.parse(readFileSync(backupPath, 'utf8'));
}

export function describePlan(plan) {
  const lines = [
    `복원할 안전 정책 사본 버전: ${plan.backupRevision} (서비스: ${plan.service}) · 현재 시험 정책 버전: ${plan.expectedRevision}`,
    plan.unchanged ? '바뀔 항목 없음: 현재 메모 정책이 사본과 같습니다.' : `바뀔 항목: 추가 ${plan.added.length}개, 제거 ${plan.removed.length}개`,
    ...plan.added.map((route) => `  + ${route}`), ...plan.removed.map((route) => `  - ${route}`),
    `보존: 다른 서비스 규칙 ${plan.preservedOtherRoutes.length}개, 감사 기록 ${plan.preservedAuditEntries}줄`,
    `확인 코드: ${plan.confirmation}`,
  ];
  return lines.join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { raw, config, state } = loadState();
    const backup = loadBackup();
    const plan = planPolicyRestore(state, backup);
    const at = process.argv.indexOf('--apply');
    process.stdout.write(`${describePlan(plan)}\n`);
    if (at === -1) {
      process.stdout.write('미리보기만 했습니다. 되돌리려면 npm run policy:restore -- --apply <확인코드>\n');
    } else {
      const next = applyPolicyRestore(state, backup, process.argv[at + 1]);
      const eol = raw.includes('\r\n') ? '\r\n' : '\n';
      writeFileSync(configPath, `${JSON.stringify({ ...config, policyRevision: next.policyRevision, allowedRoutes: next.allowedRoutes }, null, 2).replace(/\n/gu, eol)}${eol}`, 'utf8');
      appendFileSync(auditPath, `${JSON.stringify({ ...next.audit.at(-1), at: new Date().toISOString() })}\n`, 'utf8');
      process.stdout.write(`시험 정책을 사본 버전으로 되돌렸습니다(정책 버전 ${next.policyRevision}). 감사 기록은 한 줄만 더했습니다.\n`);
    }
  } catch (error) {
    process.stderr.write(`정책 복원 첫 오류(중단): ${error.message}\n`);
    process.exitCode = 1;
  }
}
