// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
async function probe(app, path) {
  const response = await fetch(new URL(path, app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let data = null;
  if (response.ok) {
    try { data = await response.json(); } catch { /* non-JSON is not exposed data */ }
  }
  return { status: response.status, data };
}

export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  const file = await probe(app, '/data.json');
  const fileVisible = file.data?.sampleMarker === config.sampleMarker || Array.isArray(file.data?.notes);
  const api = await probe(app, '/api/notes');
  const count = Array.isArray(api.data?.notes) ? api.data.notes.length : 0;
  return [
    { attackId: 'static_data_json_read', expected: '/data.json에서 가상 메모가 보이지 않아야 함',
      observed: fileVisible ? '/data.json에서 가상 메모가 여전히 보임' : `/data.json에서 가상 메모가 보이지 않음 (HTTP ${file.status})` },
    { attackId: 'anonymous_api_read', expected: '3단계 전이라 비로그인 /api/notes는 열려 있음(알려진 약점)',
      observed: count > 0 ? `비로그인 요청으로 /api/notes에서 가상 메모 ${count}건이 보임` : `비로그인 요청에서 메모가 보이지 않음 (HTTP ${api.status})` },
  ];
}
