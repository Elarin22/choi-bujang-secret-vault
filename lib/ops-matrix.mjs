// 12단계 제작 2: 1~11단계 정상·금지 요청 표의 정의와 판정입니다(서버 요약과 실행 스크립트가 같은 파일을 씁니다).
// 표에는 상태 번호·요청 ID·시각 같은 가린 값만 남기고 응답 본문·토큰·메모 내용은 남기지 않습니다.
// 판정은 저장된 'passed' 글자를 믿지 않고, 저장된 관측값(observed)으로 서버가 다시 계산합니다.
// 아직 실행하지 않은 행은 not_run이며, 이 표에 없는 41종 시험 항목을 통과로 채우지 않습니다.
export const MATRIX_SCHEMA = 'vault.ops.matrix.v1';
export const ZERO_ID = '00000000-0000-4000-8000-000000000000';
const DENIED = [401, 403];

// kind: normal(정상 요청, 허용돼야 함) / forbidden(금지 요청, 거부돼야 함)
// needs: 실행에 필요한 환경변수 이름(값은 코드·표에 쓰지 않음). 없으면 not_run으로 남깁니다.
export const MATRIX_ROWS = Object.freeze([
  { id: 's1_data_json', stage: 1, kind: 'forbidden', title: '공개 자료 파일 읽기', method: 'GET', path: '/data.json', expected: 'HTTP 404', status: [404] },
  { id: 's2_config_normal', stage: 3, kind: 'normal', title: '로그인 설정 받기', method: 'GET', path: '/api/config', expected: 'HTTP 200 + 설정 값 있음', status: [200], check: 'config_keys' },
  { id: 's3_anon_list', stage: 3, kind: 'forbidden', title: '비로그인 메모 목록', method: 'GET', path: '/api/notes', expected: 'HTTP 401 또는 403', status: DENIED },
  { id: 's3_forged_token', stage: 3, kind: 'forbidden', title: '가짜 토큰 메모 목록', method: 'GET', path: '/api/notes', auth: 'forged', expected: 'HTTP 401 또는 403', status: DENIED },
  { id: 's3_anon_write', stage: 3, kind: 'forbidden', title: '비로그인 메모 추가', method: 'POST', path: '/api/notes', body: { title: 'x', body: 'x' }, expected: 'HTTP 401 또는 403', status: DENIED },
  { id: 's4_anon_item', stage: 4, kind: 'forbidden', title: '비로그인 메모 한 건 읽기', method: 'GET', path: `/api/notes/${ZERO_ID}`, expected: 'HTTP 401 또는 403', status: DENIED },
  { id: 's4_own_list', stage: 4, kind: 'normal', title: '내 메모 목록(내 토큰)', method: 'GET', path: '/api/my/notes', auth: 'token_a', needs: ['OPS_TOKEN_A'], expected: 'HTTP 200 + 배열', status: [200], check: 'array' },
  { id: 's4_other_owner', stage: 4, kind: 'forbidden', title: '남의 메모 읽기(B 토큰으로 A 메모)', method: 'GET', path: '/api/notes/:id', auth: 'token_b', needs: ['OPS_TOKEN_B', 'OPS_NOTE_ID_A'], expected: 'HTTP 403', status: [403] },
  { id: 's5_direct_data_api', stage: 5, kind: 'forbidden', title: '공개 키로 원본 자료 경로 직접 읽기', method: 'GET', path: '(원본 API)', special: 'direct', expected: '거부(HTTP 4xx) 또는 빈 결과', check: 'direct_denied' },
  { id: 's8_anon_notice_read', stage: 8, kind: 'forbidden', title: '비로그인 공지 목록', method: 'GET', path: '/api/notices', expected: 'HTTP 401 또는 403', status: DENIED },
  { id: 's8_anon_notice_edit', stage: 8, kind: 'forbidden', title: '비로그인 공지 수정', method: 'PUT', path: `/api/notices/${ZERO_ID}`, body: { title: 'x' }, expected: 'HTTP 401 또는 403', status: DENIED },
  { id: 's8_student_notice_edit', stage: 8, kind: 'forbidden', title: '일반 학생 공지 수정', method: 'PUT', path: '/api/notices/:id', body: { title: 'x' }, auth: 'token_a', needs: ['OPS_TOKEN_A', 'OPS_NOTICE_ID'], expected: 'HTTP 403', status: [403] },
  { id: 's10_anon_restore', stage: 10, kind: 'forbidden', title: '비로그인 메모 복원', method: 'POST', path: `/api/restore/${ZERO_ID}`, expected: 'HTTP 401 또는 403', status: DENIED },
  { id: 's11_device_status', stage: 11, kind: 'normal', title: '기기 승인 상태 조회', method: 'GET', path: '/api/device-status', expected: 'HTTP 200 + 승인 상태 형식', status: [200], check: 'connection_schema' },
  { id: 's11_device_request', stage: 11, kind: 'forbidden', title: '승인 요청만으로 승인되기', method: 'POST', path: '/api/device-approval', expected: 'HTTP 200 또는 503, 요청만으로 approved 안 됨', status: [200, 503], check: 'not_granted' },
  { id: 's12_ops_summary', stage: 12, kind: 'normal', title: '작전실 요약 조회', method: 'GET', path: '/api/ops-summary', expected: 'HTTP 200 + 요약 형식', status: [200], check: 'ops_schema' },
  { id: 's12_ops_write', stage: 12, kind: 'forbidden', title: '작전실 요약에 쓰기', method: 'POST', path: '/api/ops-summary', expected: 'HTTP 405', status: [405] },
]);

const CHECKS = {
  config_keys: (o) => o.hasKeys === true,
  array: (o) => o.isArray === true,
  connection_schema: (o) => o.schema === 'vault.connection.v1',
  not_granted: (o) => o.approval !== 'approved',
  ops_schema: (o) => o.schema === 'vault.ops.summary.v1',
  direct_denied: (o) => (Number.isSafeInteger(o.status) && o.status >= 400) || o.rows === 0,
};

// 관측값으로 통과·실패를 계산합니다. 관측값이 없으면 호출하지 않습니다(not_run).
export function evaluate(row, observed) {
  if (!observed || typeof observed !== 'object') return 'not_run';
  const statusOk = !row.status || row.status.includes(observed.status);
  const checkOk = !row.check || CHECKS[row.check]?.(observed) === true;
  return statusOk && checkOk ? 'passed' : 'failed';
}

const text = (value, max) => (typeof value === 'string' && /^[A-Za-z0-9:_.\-]+$/u.test(value) && value.length <= max ? value : null);
const when = (value) => (typeof value === 'string' && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : null);

// 저장된 기록에서 알려진 필드만 꺼냅니다. 그 밖의 값(본문·토큰 등)은 있어도 버립니다.
export function cleanObserved(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const out = {};
  if (Number.isSafeInteger(raw.status)) out.status = raw.status;
  if (typeof raw.schema === 'string' && raw.schema.length <= 40 && /^[A-Za-z0-9._-]+$/u.test(raw.schema)) out.schema = raw.schema;
  if (['approved', 'pending', 'denied', 'unavailable'].includes(raw.approval)) out.approval = raw.approval;
  if (typeof raw.isArray === 'boolean') out.isArray = raw.isArray;
  if (typeof raw.hasKeys === 'boolean') out.hasKeys = raw.hasKeys;
  if (Number.isSafeInteger(raw.rows) && raw.rows >= 0) out.rows = raw.rows;
  return Object.keys(out).length ? out : null;
}

export function readMatrix(file) {
  const byId = new Map(Array.isArray(file?.results) ? file.results.filter((r) => r && typeof r.id === 'string').map((r) => [r.id, r]) : []);
  const valid = file?.schema === MATRIX_SCHEMA;
  const rows = MATRIX_ROWS.map((row) => {
    const saved = valid ? byId.get(row.id) : undefined;
    const observed = saved?.ran === true ? cleanObserved(saved.observed) : null;
    const base = { id: row.id, stage: row.stage, kind: row.kind, title: row.title, method: row.method, path: row.path, expected: row.expected };
    if (!observed) return { ...base, result: 'not_run', reason: text(saved?.reason, 40) ?? 'not_executed', actual: null, requestId: null, edgeId: null, checkedAt: null };
    return { ...base, result: evaluate(row, observed), actual: observed.status ?? null,
      requestId: text(saved.requestId, 64), edgeId: text(saved.edgeId, 80), checkedAt: when(saved.checkedAt), reason: null };
  });
  const count = (result) => rows.filter((r) => r.result === result).length;
  return {
    status: rows.some((r) => r.result !== 'not_run') ? 'recorded' : 'not_run',
    recordedAt: valid ? when(file.runAt) : null,
    total: rows.length, passed: count('passed'), failed: count('failed'), notRun: count('not_run'),
    normalPassed: rows.filter((r) => r.kind === 'normal' && r.result === 'passed').length,
    forbiddenPassed: rows.filter((r) => r.kind === 'forbidden' && r.result === 'passed').length,
    // 41종 공격 시험은 이 표의 행이 아니며, 이 저장소에서는 실행하지 않았습니다.
    suite41: { total: 41, status: 'not_run' },
    rows,
  };
}