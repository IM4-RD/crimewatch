/* CrimeWatch Service Worker v2.0 */
const CACHE   = 'cw-v3';
const SYNC_TAG = 'cw-sync';
const API = self.location.port === '8080' ? 'http://127.0.0.1:8000' : '';

const PRECACHE = ['/', '/index.html', '/js/db.js', '/js/crypto.js', '/js/api.js'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(e.request.clone()).catch(() =>
        new Response(JSON.stringify({ offline: true, error: 'Network unavailable' }), {
          status: 503, headers: { 'Content-Type': 'application/json' }
        })
      )
    );
    return;
  }
  e.respondWith(
    caches.match(e.request).then(cached => cached || fetch(e.request).then(res => {
      if (res && res.status === 200 && res.type !== 'opaque') {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
      }
      return res;
    }).catch(() => caches.match('/index.html')))
  );
});

self.addEventListener('sync', e => {
  if (e.tag === SYNC_TAG) e.waitUntil(syncReports());
});

self.addEventListener('periodicsync', e => {
  if (e.tag === 'cw-periodic') e.waitUntil(syncReports());
});

self.addEventListener('message', e => {
  if (e.data?.type === 'SYNC_NOW') syncReports().then(r => e.source?.postMessage({ type: 'SYNC_DONE', ...r }));
});

// ── IDB helpers (inline, no imports in SW) ────────────────────
function idbOpen() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('crimewatch-idb', 1);
    r.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('reports')) {
        const s = db.createObjectStore('reports', { keyPath: 'client_id' });
        s.createIndex('status', 'status', { unique: false });
        s.createIndex('created_at', 'created_at', { unique: false });
      }
      if (!db.objectStoreNames.contains('queue'))
        db.createObjectStore('queue', { keyPath: 'client_id' });
      if (!db.objectStoreNames.contains('meta'))
        db.createObjectStore('meta', { keyPath: 'key' });
    };
    r.onsuccess = e => res(e.target.result);
    r.onerror   = e => rej(e.target.error);
  });
}

function idbGetQueue() {
  return idbOpen().then(db => new Promise((res, rej) => {
    const r = db.transaction('queue', 'readonly').objectStore('queue').getAll();
    r.onsuccess = e => res(e.target.result);
    r.onerror   = e => rej(e.target.error);
  }));
}

function idbMarkSynced(client_id, server_id) {
  return idbOpen().then(db => new Promise((res, rej) => {
    const tx = db.transaction(['reports', 'queue'], 'readwrite');
    const rStore = tx.objectStore('reports');
    const gr = rStore.get(client_id);
    gr.onsuccess = e => {
      const rep = e.target.result;
      if (rep) { rep.status = 'synced'; rep.server_id = server_id; rep.synced_at = new Date().toISOString(); rStore.put(rep); }
      tx.objectStore('queue').delete(client_id);
    };
    tx.oncomplete = () => res();
    tx.onerror    = e => rej(e.target.error);
  }));
}

async function syncReports() {
  const pending = await idbGetQueue().catch(() => []);
  if (!pending.length) return { synced: 0, failed: 0 };
  let synced = 0, failed = 0;
  try {
    const res = await fetch(`${API}/api/reports/bulk-sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reports: pending }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    for (const r of data.results) {
      if (r.status === 'synced' || r.status === 'already_synced') {
        await idbMarkSynced(r.client_id, r.server_id);
        synced++;
      } else failed++;
    }
    const clients = await self.clients.matchAll({ type: 'window' });
    clients.forEach(c => c.postMessage({ type: 'SYNC_DONE', synced, failed }));
  } catch (err) {
    failed = pending.length;
    const clients = await self.clients.matchAll({ type: 'window' });
    clients.forEach(c => c.postMessage({ type: 'SYNC_FAILED', error: err.message }));
  }
  return { synced, failed };
}
