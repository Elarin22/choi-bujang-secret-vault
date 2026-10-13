import { readFileSync } from 'node:fs';
import { runRuleCheck } from '../src/rule-check.mjs';
import { collectOperationsStatus } from '../src/operations-status.mjs';

// GET /api/checks?case=<사례>: 고정된 가상 입력으로 판정기·탐지 규칙을 실행한 결과(ready)만 돌려준다. 사용자 입력을 코드로 실행하지 않는다.
// GET /api/checks: 작전실 화면이 읽는 실제 관측(/api/operations-status 와 같은 응답). 메모 본문·토큰·기기 키는 담지 않는다.
export default async function handler(req, res) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  if (req.query?.case !== undefined) {
    const result = await runRuleCheck(String(req.query.case));
    return result ? res.status(200).json(result) : res.status(400).json({ error: 'unknown_check' });
  }
  try {
    const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
    const matrix = JSON.parse(readFileSync(new URL('../data/attack-matrix.json', import.meta.url), 'utf8'));
    return res.status(200).json(await collectOperationsStatus(config, matrix, { commit: process.env.VERCEL_GIT_COMMIT_SHA }));
  } catch { return res.status(503).json({ error: 'observation_unavailable' }); }
}
