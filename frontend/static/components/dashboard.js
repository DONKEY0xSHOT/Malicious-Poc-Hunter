import { html, useState, useEffect } from "../app.js";
import { getStats, getLatestScan, getFindings } from "../api.js";
import { navigate } from "../app.js";

function timeAgo(iso) {
  if (!iso) return "never";
  const diff = (Date.now() - new Date(iso)) / 1000;
  if (diff < 60)  return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function ScanBanner({ scan }) {
  if (!scan) return html`<div class="scan-banner"><span class="text-muted">No scans yet.</span></div>`;
  const running = scan.status === "running";
  return html`
    <div class="scan-banner">
      <div>
        <span class="dot ${running ? "dot-yellow" : "dot-green"}"></span>
        <strong>${running ? "Scan in progress…" : "Last scan completed"}</strong>
        <span class="text-muted ml-1">${timeAgo(scan.finished_at || scan.started_at)}</span>
      </div>
      <div class="text-muted" style="font-size:0.8rem">
        ${scan.repos_scanned} scanned · ${scan.repos_flagged} flagged
      </div>
    </div>
  `;
}

function StatsBar({ stats }) {
  if (!stats) return html`<div class="stats-bar"><div class="loading">Loading stats…</div></div>`;
  return html`
    <div class="stats-bar">
      <div class="stat-card">
        <div class="value" style="color:var(--accent)">${stats.total_scanned.toLocaleString()}</div>
        <div class="label">Repos Scanned</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:var(--danger)">${stats.total_flagged.toLocaleString()}</div>
        <div class="label">Flagged</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:var(--warning)">${stats.rules_count}</div>
        <div class="label">YARA Rules</div>
      </div>
    </div>
  `;
}

function FindingCard({ finding }) {
  const rules = finding.rules_triggered || [];
  return html`
    <div class="card mb-2" style="cursor:pointer" onClick=${() => navigate(`/findings/${finding.id}`)}>
      <div class="flex items-center gap-2" style="justify-content:space-between;margin-bottom:0.5rem">
        <a href="/findings/${finding.id}"
           onClick=${e => { e.preventDefault(); navigate(`/findings/${finding.id}`); }}
           style="font-weight:600;font-size:0.95rem">${finding.repo_full_name}</a>
        <span class="badge badge-red">Suspicious</span>
      </div>
      <div class="flex items-center gap-1" style="flex-wrap:wrap;margin-bottom:0.5rem">
        ${rules.map(r => html`<span class="badge badge-blue">${r}</span>`)}
      </div>
      <div class="flex items-center gap-2 text-muted" style="font-size:0.8rem">
        <span>⬆ ${finding.vote_score}</span>
        <span>💬 ${finding.comment_count}</span>
        <span>${timeAgo(finding.scanned_at)}</span>
        <span>${finding.repo_size_kb}KB</span>
      </div>
    </div>
  `;
}

export function DashboardPage() {
  const [stats, setStats]   = useState(null);
  const [scan, setScan]     = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading]   = useState(true);

  useEffect(() => {
    Promise.all([getStats(), getLatestScan(), getFindings({ status: "suspicious", per_page: 10 })])
      .then(([s, sc, f]) => {
        setStats(s);
        setScan(sc);
        setFindings(f?.findings || []);
      })
      .finally(() => setLoading(false));
  }, []);

  return html`
    <div class="container">
      <div class="page-heading">Dashboard</div>
      ${html`<${StatsBar} stats=${stats} />`}
      ${html`<${ScanBanner} scan=${scan} />`}
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem">
        <strong>Recent Suspicious Findings</strong>
        <a href="/findings" onClick=${e => { e.preventDefault(); navigate("/findings"); }} class="btn btn-ghost btn-sm">
          View All →
        </a>
      </div>
      ${loading && html`<div class="loading">Loading…</div>`}
      ${!loading && findings.length === 0 && html`<div class="text-muted" style="text-align:center;padding:2rem">No findings yet. The scanner will run shortly.</div>`}
      ${findings.map(f => html`<${FindingCard} finding=${f} />`)}
    </div>
  `;
}
