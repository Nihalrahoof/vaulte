const CACHE_NAME = "vaultly-v2"
const ASSETS = [
  "/manifest.webmanifest",
  "/static/styles.css",
  "/static/icons/icon-192.jpg",
  "/static/icons/icon-512.jpg",
]

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)))
  self.skipWaiting()
})

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.map((k) => k !== CACHE_NAME && caches.delete(k)))))
  self.clients.claim()
})

self.addEventListener("fetch", (event) => {
  const { request } = event
  if (request.method !== "GET") return

  // Network-first for navigations and HTML requests to avoid stale pages after POST-redirect
  const isNavigation = request.mode === "navigate"
  const accept = request.headers.get("Accept") || ""
  const wantsHTML = accept.includes("text/html")
  if (isNavigation || wantsHTML) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          // do NOT cache HTML; just return fresh response
          return response
        })
        .catch(() => caches.match("/")),
    )
    return
  }

  // Cache-first for static assets
  event.respondWith(
    caches.match(request).then((cached) => {
      const network = fetch(request).then((response) => {
        if (response && response.status === 200) {
          const respClone = response.clone()
          caches.open(CACHE_NAME).then((cache) => cache.put(request, respClone))
        }
        return response
      })
      return cached || network
    }),
  )
})
