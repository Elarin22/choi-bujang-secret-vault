// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

async function probe(app, path, init = {}) {
  const response = await fetch(new URL(path, app), {
    redirect: 'error', signal: AbortSignal.timeout(10000), ...init,
  });
  let data = null;
  if (response.ok) {
    try { data = await response.json(); } catch { /* non-JSON is not exposed data */ }
  }
  return { status: response.status, data };
}

const rejected = (r) => r.status === 401 || r.status === 403;

export async function runAttackChecks(config) {
  if (![3, 4, 5, 6, 7, 8].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  const issuer = config.identityProvider?.issuer;
  if (typeof issuer !== 'string' || issuer.includes('REPLACE')) {
    throw new Error('aleph.config.json의 identityProvider에 실제 Supabase Project URL을 넣어 주세요.');
  }
  const forged = `${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({ iss: issuer, aud: 'authenticated',
    role: 'authenticated', sub: '00000000-0000-4000-8000-000000000000', exp: 4102444800 })}.${b64('forged')}`;
  const file = await probe(app, '/data.json');
  const anon = await probe(app, '/api/notes');
  const fake = await probe(app, '/api/notes', { headers: { Authorization: `Bearer ${forged}` } });
  const write = await probe(app, '/api/notes', { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: 'x', body: 'x' }) });
  let direct = null;
  if (config.step >= 4) {
    try {
      const conf = await (await fetch(new URL('/api/config', app), { signal: AbortSignal.timeout(10000) })).json();
      const original = typeof config.originalApiUrl === 'string' && config.originalApiUrl.startsWith('https://')
        ? config.originalApiUrl : new URL('/rest/v1/notes', conf.supabaseUrl).href;
      const response = await fetch(`${original}?select=id&limit=1`, {
        redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { apikey: conf.publishableKey, Authorization: `Bearer ${conf.publishableKey}` } });
      const rows = response.ok ? await response.json().catch(() => null) : null;
      direct = { status: response.status, rows: Array.isArray(rows) ? rows.length : 0 };
    } catch { direct = { status: 0, rows: 0 }; }
  }
  let local = null;
  let stepUpLocal = null;
  let zoneLocal = null;
  if (config.step >= 6) {
    const { decide } = await import('./decider.mjs');
    const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
    const { normal } = fixtureRequests();
    const ok = await decide(normal);
    const bad = await decide({ ...normal, requestId: normal.requestId, deviceRegistered: false });
    const { suspicious } = fixtureRequests();
    const risky = await decide(suspicious);
    const again = await decide({ ...suspicious, requestId: normal.requestId, stepUp: { verified: true, authAgeSeconds: 60 } });
    const forged = await decide({ ...suspicious, signals: { ...suspicious.signals, source: 'client_header' } });
    if (config.step >= 7) {
      stepUpLocal = `로컬 가상 사건: 정상 ${ok.decision}, 복합 이상 ${risky.decision}(${risky.reasonCode}), 다시 확인 뒤 ${again.decision}, 출처 위조 신호 ${forged.decision}(신호로 쓰지 않음). 심판 판정이 아님`;
    }
    if (config.step >= 8) {
      const own = await decide({ ...normal, requestId: normal.requestId });
      const edit = await decide({ ...normal, requestId: normal.requestId, method: 'PUT', path: '/notices/demo', route: 'PUT /notices/:id' });
      const unknown = await decide({ ...normal, requestId: normal.requestId, path: '/notes/export', route: 'GET /notes/:id' });
      const other = await decide({ ...normal, requestId: normal.requestId, method: 'GET', path: '/admin', route: 'GET /admin' });
      zoneLocal = `로컬 가상 요청: 자기 메모 ${own.decision}, 공지 수정 ${edit.decision}(${edit.reasonCode}), :id 자리 export ${unknown.decision}, 알 수 없는 경로 ${other.decision}(${other.reasonCode}). 심판 판정이 아님`;
    }
    local = `로컬 가상 요청: 등록 기기 ${ok.decision}(${ok.reasonCode}), 미등록 기기 ${bad.decision}(${bad.reasonCode}). 심판 판정이 아님`;
  }
  let notice = null;
  if (config.step >= 8) {
    const id = '00000000-0000-4000-8000-000000000000';
    notice = {
      read: await probe(app, '/api/notices'),
      edit: await probe(app, `/api/notices/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: 'x' }) }),
    };
  }
  const seen = (r) => Array.isArray(r.data) && r.data.length > 0;
  return [
    { attackId: 'static_data_json_read', expected: '/data.json에서 가상 메모가 보이지 않아야 함',
      observed: file.status === 404 ? '/data.json에서 가상 메모가 보이지 않음 (HTTP 404)' : `/data.json 응답 HTTP ${file.status}, 확인 필요` },
    { attackId: 'anonymous_api_read', expected: '로그인 없이 /api/notes를 부르면 거부',
      observed: rejected(anon) ? `비로그인 요청이 거부됨 (HTTP ${anon.status})` : `비로그인 요청이 거부되지 않음 (HTTP ${anon.status}${seen(anon) ? ', 메모 보임' : ''})` },
    { attackId: 'forged_token_read', expected: '서명이 가짜인 토큰은 거부',
      observed: rejected(fake) ? `가짜 토큰이 거부됨 (HTTP ${fake.status})` : `가짜 토큰이 거부되지 않음 (HTTP ${fake.status})` },
    { attackId: 'anonymous_api_write', expected: '로그인 없이 메모 추가는 거부',
      observed: rejected(write) ? `비로그인 추가 요청이 거부됨 (HTTP ${write.status})` : `비로그인 추가 요청이 거부되지 않음 (HTTP ${write.status})` },
    ...(local ? [{ attackId: 'device_registered_local', expected: '등록 기기는 allow, 미등록 기기는 deny·device_not_registered',
      observed: local }] : []),
    ...(stepUpLocal ? [
      { attackId: 'step_up_local', expected: '정상 사건은 allow, 복합 이상 사건은 step_up, 다시 확인 뒤 allow', observed: stepUpLocal },
      { attackId: 'step_up_real_block', expected: '다시 로그인 전에는 실제 자료가 막히고 새 로그인 뒤 허용됨',
        observed: '미실행: 이 저장소 자료 API는 판정기 결과를 받지 않아 실제 재로그인 차단은 시험하지 않음' }] : []),
    ...(notice ? [
      { attackId: 'anonymous_notice_read', expected: '로그인 없이 공지 목록을 부르면 거부',
        observed: rejected(notice.read) ? `비로그인 공지 조회가 거부됨 (HTTP ${notice.read.status})` : `비로그인 공지 조회가 거부되지 않음 (HTTP ${notice.read.status})` },
      { attackId: 'anonymous_notice_edit', expected: '로그인 없이 공지 수정은 거부',
        observed: rejected(notice.edit) ? `비로그인 공지 수정이 거부됨 (HTTP ${notice.edit.status})` : `비로그인 공지 수정이 거부되지 않음 (HTTP ${notice.edit.status})` },
      { attackId: 'zone_rules_local', expected: '자기 메모 allow, 공지 수정·알 수 없는 경로·export 자리 deny', observed: zoneLocal }] : []),
    ...(direct ? [{ attackId: 'anon_data_api_read', expected: 'anon 키로 Supabase Data API에서 notes를 직접 읽을 수 없어야 함',
      observed: direct.status === 0 ? 'Data API 직접 확인 실패(주소·키 설정 확인 필요)'
        : direct.status >= 400 || direct.rows === 0
          ? `anon 키 직접 읽기가 거부되거나 빈 결과임 (HTTP ${direct.status})` : `anon 키로 notes ${direct.rows}건이 읽힘 (HTTP ${direct.status})` }] : []),
  ];
}
