import { connectionView } from './connection-model.mjs';
const $ = id => document.getElementById(id);
let state = null;
function render() {
  const view = connectionView(state, navigator.onLine);
  $('approval-state').textContent = view.label; $('approval-detail').textContent = view.detail;
  $('open-vault').disabled = !view.canOpen; $('request-approval').disabled = !navigator.onLine;
  $('checked-at').textContent = state?.checkedAt ? `서버 확인 시각: ${new Date(state.checkedAt).toLocaleString('ko-KR')}` : '서버 상태 미확인';
}
async function refresh() {
  state = null; render();
  if (!navigator.onLine) return;
  try { const response = await fetch('/api/device-status', { cache: 'no-store' });
    if (response.ok) state = await response.json();
  } catch { state = null; }
  render();
}
$('refresh-approval').onclick = refresh;
$('request-approval').onclick = async () => {
  state = null; render();
  try { const response = await fetch('/api/device-approval', { method: 'POST', cache: 'no-store' });
    state = await response.json(); render();
    if (!response.ok) $('approval-detail').textContent = '공식 접속 도구가 연결되지 않아 승인 요청을 전달하지 못했습니다. 권한은 변경되지 않았습니다.';
  } catch { render(); }
};
$('open-vault').onclick = async () => { await refresh(); if (connectionView(state, navigator.onLine).canOpen) location.assign('/vault.html'); };
window.addEventListener('offline', () => { state = null; render(); });
window.addEventListener('online', refresh);
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/connect-sw.js', { scope: '/' }).catch(() => {});
await refresh();
