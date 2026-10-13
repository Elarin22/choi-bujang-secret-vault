const CACHE = 'byte-back-connect-public-v2';
const PUBLIC_UI = ['/','/connect.html','/connect.js','/operations.css','/connect.webmanifest','/connect-icon.svg'];
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(PUBLIC_UI))));
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin || !PUBLIC_UI.includes(url.pathname) || url.search) return;
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
});
