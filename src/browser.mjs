import { createClient } from '@supabase/supabase-js';
import { createApprovedAccess } from './approved-access.mjs';
const $ = id => document.getElementById(id);
let auth, session, editing = null;
const message = text => { $('status').textContent = text; };
function lockWorkspace() {
  $('login').hidden = true; $('logout').hidden = true; $('workspace').hidden = true;
  $('notes').replaceChildren(); clearEditor();
  message('기기 승인이 확인되지 않았습니다. 승인 전에는 자료를 표시하지 않습니다.');
}
const access = createApprovedAccess({
  isOnline: () => navigator.onLine,
  onLock: lockWorkspace,
  readState: async () => {
    const response = await fetch('/api/device-status', { cache: 'no-store', credentials: 'same-origin' });
    return response.ok ? response.json() : null;
  },
});
function clearEditor() {
  editing = null; $('editor').reset(); $('save').textContent = '메모 추가'; $('cancel').hidden = true;
}
async function api(path = '', method = 'GET', body) {
  const { data } = await auth.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new Error('로그인이 필요합니다.');
  const response = await fetch(`/api/notes${path}`, {
    method, cache: 'no-store', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(response.status === 401 ? '로그인이 만료됐습니다. 다시 로그인하세요.' : `요청에 실패했습니다 (${response.status}).`);
  return result;
}
async function listNotes() {
  try {
    const checked = await access.run(() => session ? api() : null);
    if (!checked.allowed) return;
    $('login').hidden = !!session; $('logout').hidden = !session; $('workspace').hidden = !session;
    if (!session) { message('로그인하지 않은 상태입니다.'); return; }
    const notes = checked.value;
    $('notes').replaceChildren(...notes.map(note => {
      const item = document.createElement('li');
      const title = document.createElement('strong'); title.textContent = note.title;
      const content = document.createElement('span'); content.textContent = note.body;
      const edit = document.createElement('button'); edit.textContent = '수정';
      edit.onclick = () => { editing = note.id; $('title').value = note.title; $('body').value = note.body; $('save').textContent = '수정 저장'; $('cancel').hidden = false; };
      const remove = document.createElement('button'); remove.textContent = '삭제';
      remove.onclick = async () => { try { const result = await access.run(() => api(`/${note.id}`, 'DELETE')); if (!result.allowed) return; clearEditor(); await listNotes(); } catch (error) { lockWorkspace(); message(error.message); } };
      item.append(title, content, edit, remove); return item;
    }));
    if (!notes.length) { const item = document.createElement('li'); item.textContent = '가상 메모를 추가해 보세요.'; $('notes').append(item); }
    message('승인된 기기에서 내 메모를 확인했습니다.');
  } catch (error) { lockWorkspace(); message(error.message); }
}
function showSession(next) {
  access.invalidate();
  session = next;
  listNotes();
}
window.addEventListener('offline', () => access.invalidate());
window.addEventListener('online', () => showSession(session));
window.addEventListener('pagehide', () => access.invalidate());
window.addEventListener('pageshow', () => { if (auth) showSession(session); });
document.addEventListener('visibilitychange', () => {
  if (document.hidden) access.invalidate(); else if (auth) showSession(session);
});
setInterval(() => { if (!document.hidden && auth) access.run(() => null).catch(() => access.invalidate()); }, 15000);
try {
  const response = await fetch('/api/auth-config', { cache: 'no-store' });
  if (!response.ok) throw new Error('공개 로그인 키 설정이 필요합니다.');
  const config = await response.json();
  auth = createClient(config.url, config.publishableKey, { auth: { persistSession: false, autoRefreshToken: true, detectSessionInUrl: false } });
  auth.auth.onAuthStateChange((_event, next) => { queueMicrotask(() => showSession(next)); });
  showSession((await auth.auth.getSession()).data.session);
  $('login').onsubmit = async event => {
    event.preventDefault();
    const password = $('password').value; $('password').value = '';
    try {
      const result = await access.run(() => auth.auth.signInWithPassword({ email: $('email').value, password }));
      if (result.allowed && result.value.error) message('로그인에 실패했습니다.');
    } catch { lockWorkspace(); message('로그인 요청을 완료하지 못했습니다.'); }
  };
  $('logout').onclick = async () => {
    const { error } = await auth.auth.signOut({ scope: 'local' });
    if (error) message('로그아웃에 실패했습니다.'); else showSession(null);
  };
  $('cancel').onclick = clearEditor;
  $('editor').onsubmit = async event => {
    event.preventDefault();
    try {
      const result = await access.run(() => api(editing ? `/${editing}` : '', editing ? 'PUT' : 'POST', { title: $('title').value, body: $('body').value }));
      if (!result.allowed) return;
      clearEditor(); await listNotes();
    } catch (error) { lockWorkspace(); message(error.message); }
  };
} catch (error) { message(error.message); $('login').querySelector('button').disabled = true; }
