// sw.js — deliberately minimal.
//
// The only job this has is to make the app installable (Chrome/Edge won't
// offer "Install app" without a registered service worker with a fetch
// handler) and to make the shell load instantly on repeat visits.
//
// SECURITY NOTE: this never caches anything under /api/ — every API
// request is passed straight to the network, untouched. Caching an
// authenticated response (even briefly) risks serving stale or
// cross-session data; that's not a trade-off worth making for a personal
// vault. Only static, public files (HTML/CSS/JS/icons) are cached.

const CACHE_NAME = 'vaultixgustar-shell-v1';
const SHELL_FILES = [
  '/', '/index.html', '/styles.css', '/app.js',
  '/brand/icon-192.png', '/brand/icon-512.png', '/brand/favicon-32.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) => Promise.all(
      names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never touch API calls or the share-link endpoint — always network, never cached.
  if (url.pathname.startsWith('/api/')) return;
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request)
        .then((res) => {
          if (res.ok) caches.open(CACHE_NAME).then((cache) => cache.put(event.request, res.clone()));
          return res;
        })
        .catch(() => cached); // offline: fall back to whatever's cached
      return cached || network;
    })
  );
});

// ---------------------------------------------------------------------------
// Web Push: incoming notifications and clicks. The server sends only the
// event title and timing (see server/scheduler.js). Anything that does not
// parse is ignored rather than shown.
// ---------------------------------------------------------------------------
self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { data = {}; }
  const title = typeof data.title === 'string' ? data.title.slice(0, 80) : 'VAULTIXgusTAR';
  const body = typeof data.body === 'string' ? data.body.slice(0, 200) : 'You have a reminder.';
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: '/brand/icon-192.png',
      badge: '/brand/favicon-32.png',
      tag: typeof data.triggerKey === 'string' ? data.triggerKey : undefined,
      data: { url: '/?open=calendar' },
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if ('focus' in client) { client.navigate(target).catch(() => {}); return client.focus(); }
      }
      return self.clients.openWindow(target);
    })
  );
});
