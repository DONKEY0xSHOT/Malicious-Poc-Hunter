import { html, useState, useEffect, useRef } from "../app.js";
import { getFindings, getRules } from "../api.js";
import { navigate } from "../app.js";

function timeAgo(iso) {
  if (!iso) return "";
  const diff = (Date.now() - new Date(iso)) / 1000;
  if (diff < 60)   return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

function FilterBar({ filters, onFilter, rules }) {
  const [local, setLocal] = useState(filters);
  const timer = useRef(null);

  const set = (key, val) => {
    const next = { ...local, [key]: val, page: 1 };
    setLocal(next);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => onFilter(next), 300);
  };

  return html`
    <div class="filter-bar">
      <div>
        <label>Status </label>
        <select value=${local.status} onChange=${e => set("status", e.target.value)}>
          <option value="suspicious">Suspicious</option>
          <option value="clean">Clean</option>
          <option value="all">All</option>
        </select>
      </div>
      <div>
        <label>Rule </label>
        <select value=${local.rule_name || ""} onChange=${e => set("rule_name", e.target.value || undefined)}>
          <option value="">All Rules</option>
          ${(rules || []).map(r => html`<option value="${r.name}">${r.name}</option>`)}
        </select>
      </div>
      <div>
        <input
          type="text"
          placeholder="Search repo…"
          value=${local.repo_name || ""}
          onInput=${e => set("repo_name", e.target.value || undefined)}
          style="width:180px"
        />
      </div>
      <div>
        <label>From </label>
        <input type="date" value=${local.date_from || ""} onChange=${e => set("date_from", e.target.value || undefined)} />
      </div>
      <div>
        <label>To </label>
        <input type="date" value=${local.date_to || ""} onChange=${e => set("date_to", e.target.value || undefined)} />
      </div>
      <div>
        <label>Sort </label>
        <select value=${local.sort} onChange=${e => set("sort", e.target.value)}>
          <option value="newest">Newest</option>
          <option value="oldest">Oldest</option>
          <option value="most_voted">Most Voted</option>
        </select>
      </div>
    </div>
  `;
}

function StatusBadge({ status }) {
  const cls = { suspicious: "badge-red", clean: "badge-green", error: "badge-yellow", rate_limited: "badge-gray" }[status] || "badge-gray";
  const label = status ? status.charAt(0).toUpperCase() + status.slice(1) : "—";
  return html`<span class="badge ${cls}">${label}</span>`;
}

function Pagination({ page, total, perPage, onPage }) {
  const pages = Math.ceil(total / perPage);
  if (pages <= 1) return null;
  const nums = [];
  for (let i = Math.max(1, page - 2); i <= Math.min(pages, page + 2); i++) nums.push(i);
  return html`
    <div class="pagination">
      <button class="page-btn" disabled=${page <= 1} onClick=${() => onPage(page - 1)}>‹</button>
      ${page > 3 && html`<button class="page-btn" onClick=${() => onPage(1)}>1</button><span class="text-muted">…</span>`}
      ${nums.map(n => html`<button class="page-btn ${n === page ? "active" : ""}" onClick=${() => onPage(n)}>${n}</button>`)}
      ${page < pages - 2 && html`<span class="text-muted">…</span><button class="page-btn" onClick=${() => onPage(pages)}>${pages}</button>`}
      <button class="page-btn" disabled=${page >= pages} onClick=${() => onPage(page + 1)}>›</button>
    </div>
  `;
}

export function FindingsListPage() {
  const [filters, setFilters] = useState({ status: "suspicious", sort: "newest", page: 1, per_page: 20 });
  const [result, setResult]   = useState(null);
  const [rules, setRules]     = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => { getRules().then(r => setRules(r || [])); }, []);

  useEffect(() => {
    setLoading(true);
    getFindings(filters).then(r => { setResult(r); setLoading(false); });
  }, [JSON.stringify(filters)]);

  const rows = result?.findings || [];

  return html`
    <div class="container">
      <div class="page-heading">Findings</div>
      <${FilterBar} filters=${filters} onFilter=${f => setFilters(f)} rules=${rules} />
      <div class="card" style="padding:0;overflow:hidden">
        <table class="data-table">
          <thead>
            <tr>
              <th>Repository</th>
              <th>Status</th>
              <th>Rules Triggered</th>
              <th>Stars</th>
              <th>Score</th>
              <th>Scanned</th>
            </tr>
          </thead>
          <tbody>
            ${loading && html`<tr><td colspan="6" class="loading">Loading…</td></tr>`}
            ${!loading && rows.length === 0 && html`<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2rem">No findings match the current filters.</td></tr>`}
            ${rows.map(f => html`
              <tr style="cursor:pointer" onClick=${() => navigate(`/findings/${f.id}`)}>
                <td>
                  <a href="/findings/${f.id}"
                     onClick=${e => { e.preventDefault(); navigate(`/findings/${f.id}`); }}
                     style="font-weight:600">${f.repo_full_name}</a>
                  <div class="text-muted" style="font-size:0.75rem">${f.repo_size_kb}KB</div>
                </td>
                <td><${StatusBadge} status=${f.scan_status} /></td>
                <td>
                  <div class="flex items-center gap-1" style="flex-wrap:wrap">
                    ${(f.rules_triggered || []).map(r => html`<span class="badge badge-blue" style="font-size:0.7rem">${r}</span>`)}
                  </div>
                </td>
                <td class="text-muted">⭐ ${f.repo_stars}</td>
                <td><strong>${f.vote_score > 0 ? "+" : ""}${f.vote_score}</strong></td>
                <td class="text-muted">${timeAgo(f.scanned_at)}</td>
              </tr>
            `)}
          </tbody>
        </table>
      </div>
      ${result && html`
        <div class="text-muted mt-1" style="font-size:0.8rem">
          ${result.total.toLocaleString()} result${result.total !== 1 ? "s" : ""}
        </div>
      `}
      ${result && html`
        <${Pagination}
          page=${result.page}
          total=${result.total}
          perPage=${result.per_page}
          onPage=${p => setFilters(f => ({ ...f, page: p }))}
        />
      `}
    </div>
  `;
}
