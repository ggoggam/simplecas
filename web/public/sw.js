// Minimal offline-shell service worker. Caches the app shell; never caches
// API or object responses (those must always hit the server for correctness).
//
// The shell is served **network-first**: the HTML entrypoint and hashed asset
// manifest change on every deploy, and a cache-first shell would keep serving a
// stale index.html pointing at asset hashes the server no longer has — breaking
// the app after a release. So we always try the network and only fall back to
// the cache when offline. Hashed assets under /ui/assets/ are immutable, so
// those stay cache-first for speed.
const CACHE = "simplecas-shell-v3";
const SHELL = [
  "/ui/",
  "/ui/index.html",
  "/ui/manifest.webmanifest",
  "/ui/icon.svg",
  "/ui/icon-192.png",
  "/ui/icon-512.png",
  "/ui/icon-maskable-512.png",
  "/ui/apple-touch-icon.png",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  // Only handle same-origin GETs for the UI shell; bypass API + S3 traffic.
  if (e.request.method !== "GET" || !url.pathname.startsWith("/ui/")) return;

  // Immutable hashed bundles: cache-first (fast, and their content never
  // changes for a given URL).
  if (url.pathname.startsWith("/ui/assets/")) {
    e.respondWith(
      caches.match(e.request).then((hit) =>
        hit ||
        fetch(e.request).then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
          return res;
        })
      )
    );
    return;
  }

  // Everything else under /ui/ (index.html + static shell assets): network-first
  // so a new deploy is picked up immediately, falling back to the cached shell
  // (then index.html) only when the network is unavailable.
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy));
        return res;
      })
      .catch(() =>
        caches
          .match(e.request)
          .then((hit) => hit || caches.match("/ui/index.html"))
      )
  );
});
