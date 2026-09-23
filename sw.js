// RowDash service worker: keeps the app working without a network connection.
// Network first, so a new push shows up on the next launch; the cached copy is the fallback
// when offline, or when Vercel sends us to its login page because the session has expired.
const CACHE = 'rowdash-v1';
const ASSETS = [
  '/',
  '/manifest.webmanifest',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-512.png',
  '/icons/apple-touch-icon.png',
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;

  // All pages are the one app page.
  const key = req.mode === 'navigate' ? '/' : url.pathname;

  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    try {
      const res = await fetch(req);
      // Only a real, same-origin 200 is worth keeping (not a redirect to the login page).
      if (res.ok && res.type === 'basic' && !res.redirected) {
        cache.put(key, res.clone());
        return res;
      }
      return (await cache.match(key)) || res;
    } catch {
      const cached = await cache.match(key);
      if (cached) return cached;
      throw new Error('offline and not cached');
    }
  })());
});
