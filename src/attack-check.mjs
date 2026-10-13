// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
import { runBundleChecks } from './bundle-checks.mjs';
import { readFileSync } from 'node:fs';
export async function runAttackChecks(input, options) {
  // R5 bundle callers pass config; the current public example passes the URL.
  // Read only the public repository configuration, never an env file or key.
  const config = typeof input === 'string'
    ? { ...JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8')), publicAppUrl: input }
    : input;
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('invalid_check_configuration');
  if (Number.isInteger(config.step) && config.step >= 3 && config.step <= 12) return runBundleChecks(config, options);
  if (config.step === 2) {
    const app = new URL(config.publicAppUrl);
    if (app.protocol !== 'https:' || app.username || app.password || app.pathname !== '/' || app.search || app.hash) {
      throw new Error('실제 HTTPS 배포 주소를 확인하세요.');
    }
    const request = (path) => fetch(new URL(path, app), { redirect: 'error', signal: AbortSignal.timeout(10000) });
    const staticResponse = await request('/data.json');
    const staticBody = await staticResponse.text();
    let staticNotes = false;
    try { staticNotes = Array.isArray(JSON.parse(staticBody).notes) && JSON.parse(staticBody).notes.length > 0; } catch {}
    const apiResponse = await request('/api/notes');
    let count = 0;
    try { const body = await apiResponse.json(); count = Array.isArray(body.notes) ? body.notes.length : 0; } catch {}
    return [
      { attackId: 'static_note_seed', expected: '공개 정적 자료 경로는 404이며 메모 없음',
        observed: `HTTP ${staticResponse.status}; notes present: ${staticNotes}` },
      { attackId: 'anonymous_api_read', expected: '2단계의 공개 API에서 가상 카드 네 건 반환; 인증은 후속 단계',
        observed: `HTTP ${apiResponse.status}; note count: ${count}` },
    ];
  }
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
