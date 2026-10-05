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
  if (config.step !== 3) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  ];
}
