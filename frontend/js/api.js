// ERROR-PANEL — API Client
// Fetch wrapper for backend at http://127.0.0.1:8000/api

const API_BASE = 'http://127.0.0.1:8000/api';

async function apiRequest(method, path, body) {
    const token = await getToken();
    const opts = {
        method,
        headers: {
            'Content-Type': 'application/json',
            'X-API-Token': token
        },
    };
    if (body !== undefined) {
        opts.body = JSON.stringify(body);
    }
    const res = await fetch(API_BASE + path, opts);
    if (!res.ok) {
        let msg = HTTP ;
        try {
            const err = await res.json();
            msg = err.detail || msg;
        } catch (_) { /* ignore parse error */ }
        throw new Error(msg);
    }
    if (res.status === 204) return null;
    return res.json();
},
  };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(API_BASE + path, opts);
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const err = await res.json();
      msg = err.detail || msg;
    } catch (_) { /* ignore parse error */ }
    throw new Error(msg);
  }
  if (res.status === 204) return null;
  return res.json();
}

// ── Health ──────────────────────────────────────────────────────────────────
async function health() {
  return apiRequest('GET', '/health');
}

// ── Sources ─────────────────────────────────────────────────────────────────
async function listSources() {
  return apiRequest('GET', '/sources/');
}

async function createSource(data) {
  return apiRequest('POST', '/sources/', data);
}

async function getSource(id) {
  return apiRequest('GET', `/sources/${id}`);
}

async function updateSource(id, data) {
  return apiRequest('PATCH', `/sources/${id}`, data);
}

async function deleteSource(id) {
  return apiRequest('DELETE', `/sources/${id}`);
}

// ── Profiles ────────────────────────────────────────────────────────────────
async function listProfiles(filters = {}) {
  const params = new URLSearchParams();
  if (filters.status) params.set('status', filters.status);
  if (filters.protocol) params.set('protocol', filters.protocol);
  if (filters.search) params.set('search', filters.search);
  const qs = params.toString();
  return apiRequest('GET', `/profiles/${qs ? '?' + qs : ''}`);
}

async function createProfile(data) {
  return apiRequest('POST', '/profiles/', data);
}

async function getProfile(id) {
  return apiRequest('GET', `/profiles/${id}`);
}

async function updateProfile(id, data) {
  return apiRequest('PATCH', `/profiles/${id}`, data);
}

async function deleteProfile(id) {
  return apiRequest('DELETE', `/profiles/${id}`);
}

// ── Sync ────────────────────────────────────────────────────────────────────
async function syncSource(id) {
  return apiRequest('POST', `/sources/${id}/sync`);
}

// ── Quarantine ──────────────────────────────────────────────────────────────
async function listQuarantine() {
  return apiRequest('GET', '/quarantine/');
}

async function approveQuarantine(id) {
  return apiRequest('POST', `/quarantine/${id}/approve`);
}

async function rejectQuarantine(id) {
  return apiRequest('POST', `/quarantine/${id}/reject`);
}

async function blockQuarantine(id) {
  return apiRequest('POST', `/quarantine/${id}/block`);
}

// ── Security Scanner ───────────────────────────────────────────────────────
async function scanProfile(id) {
  return apiRequest('POST', `/security/scan/${id}`);
}

async function getScans(id) {
  return apiRequest('GET', `/security/scans/${id}`);
}

// ── Network Tests & Metrics ────────────────────────────────────────────────
async function runTest(profileId) {
  return apiRequest('POST', `/tests/run/${profileId}`);
}

async function getMetrics(profileId) {
  return apiRequest('GET', `/metrics?profile_id=${profileId}`);
}

async function submitMetrics(payload) {
  return apiRequest('POST', '/metrics', payload);
}

// ── Ranking & Analytics ────────────────────────────────────────────────────
async function getRanking(metric = 'score', limit = 10) {
  return apiRequest('GET', `/ranking/top?metric=${metric}&limit=${limit}`);
}

async function getAnalytics() {
  return apiRequest('GET', '/analytics/overview');
}

// ── Settings ──────────────────────────────────────────────────────────────
async function getSettings() {
  return apiRequest('GET', '/settings');
}

async function updateSettings(patch) {
  return apiRequest('PATCH', '/settings', patch);
}

// ── Logs ──────────────────────────────────────────────────────────────────
async function getLogs(limit = 100) {
  return apiRequest('GET', `/logs?limit=${limit}`);
}

// ── Backup & Export ───────────────────────────────────────────────────────
async function createBackup() {
  return apiRequest('POST', '/backup');
}

async function exportData(format = 'json') {
  const res = await fetch(API_BASE + `/export?format=${format}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res;
}

