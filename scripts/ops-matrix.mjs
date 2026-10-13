// 12단계 제작 2: 배포된 자료실에 정상·금지 요청을 실제로 보내 결과를 ops/matrix.json에 남깁니다.
//   npm run ops:matrix
// 토큰은 환경변수(OPS_TOKEN_A·OPS_TOKEN_B)에서만 읽고 어디에도 쓰거나 출력하지 않습니다. 없으면 해당 행은 미실행으로 남습니다.
// 응답 본문은 저장하지 않고 상태 번호·형식 이름 같은 가린 값만 남깁니다.
import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { MATRIX_ROWS, MATRIX_SCHEMA, evaluate, readMatrix } from '../lib/ops-matrix.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(readFileSync(resolve(root, 'aleph.config.json'), 'utf8'));
const app = new URL(config.publicAppUrl);
if (app.protocol !== 'https:' || app.pathname !== '/' || app.hostname.endsWith('.example')) {
  process.stderr.write('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.\n'); process.exit(1);
}
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const forged = `${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({ iss: config.identityProvider?.issuer, aud: 'authenticated', role: 'authenticated', sub: '00000000-0000-4000-8000-000000000000', exp: 4102444800 })}.${b64('forged')}`;
const env = (name) => (typeof process.env[name] === 'string' && process.env[name].trim() ? process.env[name].trim() : null);

async function send(row, requestId) {
  let path = row.path;
  if (row.id === 's4_other_owner') path = `/api/notes/${encodeURIComponent(env('OPS_NOTE_ID_A'))}`;
  if (row.id === 's8_student_notice_edit') path = `/api/notices/${encodeURIComponent(env('OPS_NOTICE_ID'))}`;
  const headers = { 'X-Request-Id': requestId };
  if (row.body) headers['Content-Type'] = 'application/json';
  if (row.auth === 'forged') headers.Authorization = `Bearer ${forged}`;
  if (row.auth === 'token_a') headers.Authorization = `Bearer ${env('OPS_TOKEN_A')}`;
  if (row.auth === 'token_b') headers.Authorization = `Bearer ${env('OPS_TOKEN_B')}`;
  return fetch(new URL(path, app), { method: row.method, headers, body: row.body ? JSON.stringify(row.body) : undefined,
    redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000) });
}

async function direct() {
  const conf = await (await fetch(new URL('/api/config', app), { signal: AbortSignal.timeout(10000) })).json();
  const original = typeof config.originalApiUrl === 'string' ? config.originalApiUrl : new URL('/rest/v1/notes', conf.supabaseUrl).href;
  const response = await fetch(`${original}?select=id&limit=1`, { redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { apikey: conf.publishableKey, Authorization: `Bearer ${conf.publishableKey}` } });
  const rows = response.ok ? await response.json().catch(() => null) : null;
  return { status: response.status, rows: Array.isArray(rows) ? rows.length : 0 };
}

const results = [];
for (const row of MATRIX_ROWS) {
  const missing = (row.needs ?? []).filter((name) => !env(name));
  if (missing.length) { results.push({ id: row.id, ran: false, reason: 'env_missing' }); continue; }
  const requestId = `ops-${randomUUID()}`;
  try {
    if (row.special === 'direct') {
      results.push({ id: row.id, ran: true, requestId, checkedAt: new Date().toISOString(), observed: await direct() });
      continue;
    }
    const response = await send(row, requestId);
    const data = await response.json().catch(() => null);
    const observed = { status: response.status };
    if (typeof data?.schema === 'string') observed.schema = data.schema;
    if (typeof data?.approval === 'string') observed.approval = data.approval;
    if (row.check === 'array') observed.isArray = Array.isArray(data);
    if (row.check === 'config_keys') observed.hasKeys = typeof data?.supabaseUrl === 'string' && typeof data?.publishableKey === 'string';
    results.push({ id: row.id, ran: true, requestId, edgeId: response.headers.get('x-vercel-id') ?? undefined, checkedAt: new Date().toISOString(), observed });
  } catch {
    results.push({ id: row.id, ran: false, reason: 'request_failed' });
  }
}

const file = { schema: MATRIX_SCHEMA, baseUrl: app.origin, runAt: new Date().toISOString(), results };
writeFileSync(resolve(root, 'ops', 'matrix.json'), `${JSON.stringify(file, null, 2)}\n`, 'utf8');
const view = readMatrix(file);
for (const r of view.rows) {
  const mark = r.result === 'passed' ? '통과' : r.result === 'failed' ? '실패' : '미실행';
  process.stdout.write(`[${mark}] 단계 ${r.stage} ${r.kind === 'normal' ? '정상' : '금지'} · ${r.title} · 기대 ${r.expected} · 실제 ${r.actual ?? '-'} · ${r.requestId ?? '-'} · ${r.checkedAt ?? '-'}\n`);
}
process.stdout.write(`합계 ${view.total}행: 통과 ${view.passed}, 실패 ${view.failed}, 미실행 ${view.notRun}. 41종 공격 시험은 이 표와 별개이며 미실행입니다.\n`);
if (view.failed) process.exitCode = 1;