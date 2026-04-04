/** API client module. All fetch calls go through apiFetch(). */

const BASE = "/api/v1";

let _toastFn = null;
export function registerToast(fn) { _toastFn = fn; }

async function apiFetch(path, options = {}) {
  const resp = await fetch(`${BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });

  if (resp.status === 204) return null;

  let data;
  try { data = await resp.json(); } catch { data = null; }

  if (!resp.ok) {
    const msg = data?.detail || `HTTP ${resp.status}`;
    if (_toastFn) _toastFn(msg, "error");
    const err = new Error(msg);
    err.status = resp.status;
    throw err;
  }

  return data;
}

// ---- Findings ----

export async function getFindings(filters = {}) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== null && v !== "") params.set(k, v);
  }
  return apiFetch(`/findings?${params.toString()}`);
}

export async function getFinding(id) {
  return apiFetch(`/findings/${id}`);
}

// ---- Votes ----

export async function voteFinding(id, vote) {
  return apiFetch(`/findings/${id}/vote`, {
    method: "POST",
    body: JSON.stringify({ vote }),
  });
}

// ---- Comments ----

export async function postComment(findingId, body) {
  return apiFetch(`/findings/${findingId}/comments`, {
    method: "POST",
    body: JSON.stringify({ body }),
  });
}

export async function deleteComment(findingId, commentId) {
  return apiFetch(`/findings/${findingId}/comments/${commentId}`, {
    method: "DELETE",
  });
}

// ---- Scan runs ----

export async function getScanRuns(page = 1, perPage = 20) {
  return apiFetch(`/scan-runs?page=${page}&per_page=${perPage}`);
}

export async function getLatestScan() {
  return apiFetch("/scan-runs/latest");
}

// ---- Stats / rules ----

export async function getStats() {
  return apiFetch("/stats");
}

export async function getRules() {
  return apiFetch("/rules");
}

// ---- Auth ----

export async function getMe() {
  try { return await apiFetch("/auth/me"); } catch { return null; }
}

export function loginUrl() {
  return `${BASE}/auth/github`;
}

export async function logout() {
  return apiFetch("/auth/logout", { method: "POST" });
}
