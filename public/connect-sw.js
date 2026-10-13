// 오프라인에는 공개 화면(안내)만 보관합니다. 메모·API 응답·로그인 정보는 캐시하지 않습니다.
const CACHE = 'byte-back-connect-public-v1';
const PUBLIC_UI = ['/connect.html', '/connect.js', '/connection-model.js', '/connect.webmanifest', '/connect-icon.svg'];
self.addEventListener('install', (event) => event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(PUBLIC_UI))));
self.addEventListener('activate', (event) => event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))));
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return; // 자료·승인 응답은 항상 서버에서 새로 받습니다.
  if (PUBLIC_UI.includes(url.pathname) && !url.search) {
    event.respondWith(fetch(request).catch(() => caches.match(request)));
  } else if (request.mode === 'navigate') {
    // 자료실 화면은 오프라인에서 열지 않고 안내 화면으로 보냅니다.
    event.respondWith(fetch(request).catch(() => caches.match('/connect.html')));
  }
});