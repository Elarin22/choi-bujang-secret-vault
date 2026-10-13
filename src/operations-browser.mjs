const $ = id => document.getElementById(id);
const text = value => value === null || value === undefined ? '미실행' : String(value);
function table(id, rows, fields) {
  $(id).replaceChildren(...rows.map(row => {
    const tr = document.createElement('tr');
    for (const field of fields) { const td = document.createElement('td'); td.textContent = text(row[field]); tr.append(td); }
    return tr;
  }));
}
async function refresh() {
  function clear() {
    for (const id of ['rules', 'detection', 'revocation', 'recovery', 'counts', 'official-count']) $(id).textContent = '미확인';
    $('checks').replaceChildren(); $('matrix').replaceChildren();
  }
  clear();
  $('refresh').disabled = true; $('status').textContent = '서버에서 새 요청 결과를 관측합니다.';
  try {
    const response = await fetch('/api/operations-status', { cache: 'no-store' });
    if (!response.ok) throw new Error('unavailable');
    const data = await response.json();
    if (data.schema !== 'vault.operations.v1') throw new Error('invalid');
    $('rules').textContent = data.policyRules.join(', ');
    $('detection').textContent = `${data.detection.action} · 로컬 가상 사건`;
    $('revocation').textContent = '실제 회수 집행 미연결';
    $('recovery').textContent = data.recovery.verified ? `사본 검증됨 · 버전 ${data.recovery.revision}` : '사본 검증 미확인';
    $('counts').textContent = `자기 점검 ${data.counts.passed}건 일치 · ${data.counts.failed}건 불일치 · ${data.counts.notRun}건 미실행`;
    $('official-count').textContent = `공식 엔진 41종 재현 시험 ${data.counts.officialEngineNotRun}건 미실행`;
    table('checks', data.checks, ['id', 'request', 'source', 'expected', 'observed', 'status', 'requestId', 'checkedAt']);
    table('matrix', data.attackMatrix, ['stage', 'name', 'expected', 'status', 'requestId', 'checkedAt']);
    $('status').textContent = `서버 응답 확인: ${data.checkedAt} · 배포 커밋 ${data.commit?.slice(0,12) ?? '미확인'} · 관측 ID ${data.requestId}`;
  } catch { clear(); $('status').textContent = '서버 결과를 읽지 못했습니다. 시험을 통과로 표시하지 않습니다.'; }
  finally { $('refresh').disabled = false; }
}
$('refresh').onclick = refresh;
await refresh();
