/* CrimeWatch — API client — api.js */
export const BASE = window.location.port === '8080' ? 'http://127.0.0.1:8000' : '';
let _token = null;

export const API = {
  setToken(t)  { _token = t; },
  clearToken() { _token = null; },
  getToken()   { return _token; },

  async fetch(path, opts = {}) {
    const h = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    if (_token) h['Authorization'] = `Bearer ${_token}`;
    const cfg = { ...opts, headers: h };
    if (cfg.body && typeof cfg.body === 'object') cfg.body = JSON.stringify(cfg.body);
    try {
      const res  = await fetch(BASE + path, cfg);
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw Object.assign(new Error(data.detail || `HTTP ${res.status}`), { status: res.status, data });
      return data;
    } catch (err) {
      if (err.name === 'TypeError' || err.message?.includes('fetch'))
        throw Object.assign(new Error('Server offline'), { offline: true });
      throw err;
    }
  },

  // Auth
  login:    (e, p) => API.fetch('/api/auth/login',    { method: 'POST', body: { email: e, password: p } }),
  register: (d)    => API.fetch('/api/auth/register', { method: 'POST', body: d }),
  logout:   ()     => API.fetch('/api/auth/logout',   { method: 'POST' }).catch(() => {}),
  me:       ()     => API.fetch('/api/auth/me'),
  updatePublicKey: (pk) => API.fetch('/api/auth/public-key', { method: 'PUT', body: { public_key: pk } }),

  // Keys
  getServerPublicKey: () => API.fetch('/api/keys/public'),

  // Reports
  submit:    (r)         => API.fetch('/api/reports',           { method: 'POST', body: r }),
  bulkSync:  (rs)        => API.fetch('/api/reports/bulk-sync', { method: 'POST', body: { reports: rs } }),
  list:      (params='') => API.fetch('/api/reports' + params),
  getReport: (id, decrypt=false) => API.fetch(`/api/reports/${id}${decrypt ? '?decrypt=true' : ''}`),
  updateStatus: (id, status, note) => API.fetch(`/api/reports/${id}/status`, { method: 'PATCH', body: { status, note } }),
  getHistory:   (id)     => API.fetch(`/api/reports/${id}/history`),

  // Stats
  stats: () => API.fetch('/api/stats'),

  // Admin
  listUsers:  ()           => API.fetch('/api/users'),
  updateRole: (id, role)   => API.fetch(`/api/users/${id}/role`, { method: 'PATCH', body: { role } }),

  // Media (multipart)
  async uploadMedia(reportId, file) {
    const form = new FormData();
    form.append('file', file);
    const headers = {};
    if (_token) headers['Authorization'] = `Bearer ${_token}`;
    const res = await fetch(`${BASE}/api/reports/${reportId}/media`, { method: 'POST', headers, body: form });
    if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
    return res.json();
  },

  // Health
  health: () => API.fetch('/api/health').then(d => ({ online: true, ...d })).catch(() => ({ online: false })),
};
