/* CrimeWatch — IndexedDB layer — db.js */
const DB_NAME = 'crimewatch-idb', DB_VER = 1;
let _db = null;

function openDB() {
  if (_db) return Promise.resolve(_db);
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB_NAME, DB_VER);
    r.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('reports')) {
        const s = db.createObjectStore('reports', { keyPath: 'client_id' });
        s.createIndex('status',     'status',     { unique: false });
        s.createIndex('created_at', 'created_at', { unique: false });
      }
      if (!db.objectStoreNames.contains('queue'))
        db.createObjectStore('queue', { keyPath: 'client_id' });
      if (!db.objectStoreNames.contains('meta'))
        db.createObjectStore('meta', { keyPath: 'key' });
    };
    r.onsuccess = e => { _db = e.target.result; res(_db); };
    r.onerror   = e => rej(e.target.error);
  });
}

function p(req) { return new Promise((s, j) => { req.onsuccess = e => s(e.target.result); req.onerror = e => j(e.target.error); }); }

const DB = {
  async saveReport(report) {
    const db = await openDB();
    return new Promise((res, rej) => {
      const tx = db.transaction(['reports', 'queue'], 'readwrite');
      tx.objectStore('reports').put(report);
      if (report.status === 'pending') tx.objectStore('queue').put(report);
      else tx.objectStore('queue').delete(report.client_id);
      tx.oncomplete = () => res(report);
      tx.onerror    = e => rej(e.target.error);
    });
  },

  async getAll() {
    const db = await openDB();
    return new Promise((res, rej) => {
      const r = db.transaction('reports', 'readonly').objectStore('reports').getAll();
      r.onsuccess = e => res(e.target.result.sort((a, b) => b.created_at.localeCompare(a.created_at)));
      r.onerror   = e => rej(e.target.error);
    });
  },

  async get(client_id) {
    const db = await openDB();
    return p(db.transaction('reports', 'readonly').objectStore('reports').get(client_id));
  },

  async getQueue() {
    const db = await openDB();
    return new Promise((res, rej) => {
      const r = db.transaction('queue', 'readonly').objectStore('queue').getAll();
      r.onsuccess = e => res(e.target.result);
      r.onerror   = e => rej(e.target.error);
    });
  },

  async markSynced(client_id, server_id) {
    const db = await openDB();
    return new Promise((res, rej) => {
      const tx = db.transaction(['reports', 'queue'], 'readwrite');
      const rs = tx.objectStore('reports');
      const gr = rs.get(client_id);
      gr.onsuccess = e => {
        const r = e.target.result;
        if (r) { r.status = 'synced'; r.server_id = server_id; r.synced_at = new Date().toISOString(); rs.put(r); }
        tx.objectStore('queue').delete(client_id);
      };
      tx.oncomplete = () => res();
      tx.onerror    = e => rej(e.target.error);
    });
  },

  async getMeta(k) { const db = await openDB(); const r = await p(db.transaction('meta','readonly').objectStore('meta').get(k)); return r?.value ?? null; },
  async setMeta(k, v) { const db = await openDB(); return p(db.transaction('meta','readwrite').objectStore('meta').put({ key: k, value: v })); },
  async delMeta(k) { const db = await openDB(); return p(db.transaction('meta','readwrite').objectStore('meta').delete(k)); },

  async getStats() {
    const all = await this.getAll();
    const s = { total: all.length, pending: 0, synced: 0, received: 0, reviewing: 0, investigating: 0, resolved: 0, by_type: {}, by_severity: {} };
    for (const r of all) {
      s[r.status] = (s[r.status] || 0) + 1;
      s.by_type[r.incident_type] = (s.by_type[r.incident_type] || 0) + 1;
      s.by_severity[r.severity]  = (s.by_severity[r.severity]  || 0) + 1;
    }
    return s;
  }
};

export default DB;
