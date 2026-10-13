import { crossCheck, matrixCounts, matrixRows, summaryRows } from './ops-model.js';

const $ = (id) => document.getElementById(id);

async function getJson(path) {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function draw(summary, direct) {
  const rows = summaryRows(summary);
  const body = $('rows');
  body.replaceChildren();
  for (const row of rows) {
    const tr = document.createElement('tr');
    for (const value of [row.area, row.item, row.value, row.label]) {
      const td = document.createElement('td'); td.textContent = value; tr.append(td);
    }
    tr.dataset.status = row.status ?? 'unknown';
    body.append(tr);
  }
  const mbody = $('matrix-rows');
  mbody.replaceChildren();
  for (const row of matrixRows(summary)) {
    const tr = document.createElement('tr');
    for (const value of [row.stage, row.kind, row.title, row.request, row.expected, row.actual, row.result, row.requestId, row.checkedAt]) {
      const td = document.createElement('td'); td.textContent = value; tr.append(td);
    }
    tr.dataset.result = row.raw;
    mbody.append(tr);
  }
  $('matrix-counts').textContent = matrixCounts(summary);
  $('state').textContent = rows.length ? `서버 요약을 받았습니다 (${rows.length}개 항목)` : '서버 요약을 받지 못했습니다. 아무 항목도 확인된 것이 아닙니다.';
  $('generated').textContent = summary?.generatedAt ? `서버 기록 시각: ${new Date(summary.generatedAt).toLocaleString('ko-KR')}` : '서버 기록 시각 없음';
  const cross = crossCheck(summary, direct);
  $('cross').textContent = cross.detail;
  $('cross').dataset.match = String(cross.match);
}

async function refresh() {
  $('state').textContent = '서버 요약을 불러오는 중입니다.';
  let summary = null; let direct = null;
  try { summary = await getJson('/api/ops-summary'); } catch { summary = null; }
  try { direct = await getJson('/api/device-status'); } catch { direct = null; }
  draw(summary, direct);
}

$('refresh').onclick = refresh;
await refresh();