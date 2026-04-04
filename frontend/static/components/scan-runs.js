import { html, useState, useEffect } from "../app.js";
import { getScanRuns } from "../api.js";

function StatusPill({ status }) {
  return html`<span class="status-pill status-${status}">${status}</span>`;
}

function duration(start, end) {
  if (!start || !end) return "—";
  const s = Math.round((new Date(end) - new Date(start)) / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

export function ScanRunsPage() {
  const [result, setResult]   = useState(null);
  const [page, setPage]       = useState(1);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getScanRuns(page, 20).then(r => { setResult(r); setLoading(false); });
  }, [page]);

  const runs = result?.items || [];

  return html`
    <div class="container">
      <div class="page-heading">Scan History</div>
      <div class="card" style="padding:0;overflow:hidden">
        <table class="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Started</th>
              <th>Finished</th>
              <th>Duration</th>
              <th>Status</th>
              <th>Scanned</th>
              <th>Flagged</th>
            </tr>
          </thead>
          <tbody>
            ${loading && html`<tr><td colspan="7" class="loading">Loading…</td></tr>`}
            ${!loading && runs.length === 0 && html`<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--text-muted)">No scan runs yet.</td></tr>`}
            ${runs.map(r => html`
              <tr>
                <td class="text-muted">${r.id}</td>
                <td>${new Date(r.started_at).toLocaleString()}</td>
                <td>${r.finished_at ? new Date(r.finished_at).toLocaleString() : "—"}</td>
                <td class="text-muted">${duration(r.started_at, r.finished_at)}</td>
                <td><${StatusPill} status=${r.status} /></td>
                <td>${r.repos_scanned.toLocaleString()}</td>
                <td style="color:var(--danger);font-weight:600">${r.repos_flagged}</td>
              </tr>
            `)}
          </tbody>
        </table>
      </div>
      ${result && result.total > 20 && html`
        <div class="pagination mt-2">
          <button class="page-btn" disabled=${page <= 1} onClick=${() => setPage(p => p - 1)}>‹ Prev</button>
          <span class="text-muted">${page} / ${Math.ceil(result.total / 20)}</span>
          <button class="page-btn" disabled=${page >= Math.ceil(result.total / 20)} onClick=${() => setPage(p => p + 1)}>Next ›</button>
        </div>
      `}
    </div>
  `;
}
