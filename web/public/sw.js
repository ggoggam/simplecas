// Minimal offline-shell service worker. Caches the app shell; never caches
// API or object responses (those must always hit the server for correctness).
const CACHE = "simplecas-shell-v2";
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
  e.respondWith(
    caches.match(e.request).then((hit) =>
      hit ||
      fetch(e.request)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
          return res;
        })
        .catch(() => caches.match("/ui/index.html"))
    )
  );
});
