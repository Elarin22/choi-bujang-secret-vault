import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createDeviceService } from '../lib/device.mjs';
import { MATRIX_ROWS, MATRIX_SCHEMA, cleanObserved, evaluate, readMatrix } from '../lib/ops-matrix.mjs';
import { buildOpsSummary, loadInputs } from '../lib/ops-summary.mjs';
import { matrixCounts, matrixRows } from '../public/ops-model.js';

const NOW = new Date('2026-10-13T00:00:00.000Z');
const row = (id) => MATRIX_ROWS.find((r) => r.id === id);
const saved = (id, observed, extra = {}) => ({ id, ran: true, requestId: `ops-${id}`, checkedAt: NOW.toISOString(), observed, ...extra });

test('matrix: ids are unique, every stage 1~11 request has an expectation, and the committed record starts as not_run', () => {
  assert.equal(new Set(MATRIX_ROWS.map((r) => r.id)).size, MATRIX_ROWS.length);
  assert.ok(MATRIX_ROWS.some((r) => r.kind === 'normal') && MATRIX_ROWS.some((r) => r.kind === 'forbidden'));
  assert.ok(MATRIX_ROWS.every((r) => r.title && r.method && r.path && r.expected));
  const view = readMatrix(JSON.parse(readFileSync(new URL('../ops/matrix.json', import.meta.url), 'utf8')));
  assert.deepEqual([view.status, view.passed, view.failed, view.notRun], ['not_run', 0, 0, MATRIX_ROWS.length]);
  assert.equal(view.suite41.status, 'not_run');
});

test('matrix: forbidden requests pass only when refused, normal requests only when allowed', () => {
  assert.equal(evaluate(row('s3_anon_list'), { status: 401 }), 'passed');
  assert.equal(evaluate(row('s3_anon_list'), { status: 200 }), 'failed');
  assert.equal(evaluate(row('s4_other_owner'), { status: 403 }), 'passed');
  assert.equal(evaluate(row('s4_other_owner'), { status: 404 }), 'failed');
  assert.equal(evaluate(row('s4_own_list'), { status: 200, isArray: true }), 'passed');
  assert.equal(evaluate(row('s4_own_list'), { status: 200, isArray: false }), 'failed');
  assert.equal(evaluate(row('s4_own_list'), { status: 401 }), 'failed');
  assert.equal(evaluate(row('s11_device_request'), { status: 503, approval: 'unavailable' }), 'passed');
  assert.equal(evaluate(row('s11_device_request'), { status: 200, approval: 'approved' }), 'failed');
  assert.equal(evaluate(row('s5_direct_data_api'), { status: 200, rows: 0 }), 'passed');
  assert.equal(evaluate(row('s5_direct_data_api'), { status: 200, rows: 1 }), 'failed');
  assert.equal(evaluate(row('s1_data_json'), null), 'not_run');
});

test('matrix: a stored "passed" is ignored; the server recomputes from the observed values, and unrun rows stay not_run', () => {
  const file = { schema: MATRIX_SCHEMA, runAt: NOW.toISOString(), results: [
    { ...saved('s3_anon_list', { status: 200 }), result: 'passed', status: 'passed' },
    saved('s1_data_json', { status: 404 }),
    { id: 's4_own_list', ran: false, reason: 'env_missing' },
  ] };
  const view = readMatrix(file);
  const by = (id) => view.rows.find((r) => r.id === id);
  assert.equal(by('s3_anon_list').result, 'failed');
  assert.equal(by('s1_data_json').result, 'passed');
  assert.equal(by('s4_own_list').result, 'not_run');
  assert.equal(by('s4_own_list').reason, 'env_missing');
  assert.equal(by('s3_forged_token').result, 'not_run');
  assert.deepEqual([view.passed, view.failed, view.notRun, view.total], [1, 1, MATRIX_ROWS.length - 2, MATRIX_ROWS.length]);
  assert.equal(view.forbiddenPassed, 1);
  assert.equal(view.normalPassed, 0);
  assert.equal(view.status, 'recorded');
  assert.equal(readMatrix({ schema: 'x', results: file.results }).passed, 0);
});

test('matrix: only known, short, plain fields survive; bodies, tokens and odd ids are dropped', () => {
  const cleaned = cleanObserved({ status: 200, body: 'secret note', token: 'abc', schema: 'vault.ops.summary.v1', approval: 'approved', isArray: true });
  assert.deepEqual(cleaned, { status: 200, schema: 'vault.ops.summary.v1', approval: 'approved', isArray: true });
  const view = readMatrix({ schema: MATRIX_SCHEMA, results: [saved('s1_data_json', { status: 404 }, { requestId: 'has space <x>', checkedAt: 'not a date' })] });
  const r = view.rows.find((x) => x.id === 's1_data_json');
  assert.deepEqual([r.requestId, r.checkedAt], [null, null]);
  assert.ok(!/secret note|abc|Bearer|access_token/u.test(JSON.stringify(view)));
});

test('ops summary carries the same matrix numbers the screen shows', async () => {
  const file = { schema: MATRIX_SCHEMA, runAt: NOW.toISOString(), results: [saved('s1_data_json', { status: 404 }), saved('s2_config_normal', { status: 200, hasKeys: true })] };
  const summary = buildOpsSummary({ ...loadInputs(), matrix: file, device: await createDeviceService({ now: () => NOW }).status({}, null), now: NOW });
  assert.deepEqual([summary.matrix.passed, summary.matrix.notRun], [2, MATRIX_ROWS.length - 2]);
  const rows = matrixRows(summary);
  assert.equal(rows.length, MATRIX_ROWS.length);
  assert.equal(rows.filter((r) => r.raw === 'passed').length, summary.matrix.passed);
  assert.equal(rows.find((r) => r.title === '공개 자료 파일 읽기').actual, 'HTTP 404');
  assert.match(matrixCounts(summary), /기대와 같음 2/u);
  assert.match(matrixCounts(summary), /41종 공격 시험: 미실행/u);
  assert.deepEqual(matrixRows(null), []);
  assert.match(matrixCounts(null), /확인된 것이 아닙니다/u);
});

test('ops:matrix script and attack-check: tokens never printed, Buffer is imported, step 12 is accepted', () => {
  const script = readFileSync(new URL('../scripts/ops-matrix.mjs', import.meta.url), 'utf8');
  assert.match(script, /from 'node:buffer'/u);
  assert.ok(!/(log|write)\([^)]*(OPS_TOKEN|Authorization|forged)/u.test(script));
  const attack = readFileSync(new URL('../src/attack-check.mjs', import.meta.url), 'utf8');
  assert.match(attack, /import \{ Buffer \} from 'node:buffer'/u);
  assert.match(attack, /\[3, 4, 5, 6, 7, 8, 9, 10, 11, 12\]\.includes/u);
});