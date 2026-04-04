import { html, useState, useEffect } from "../app.js";
import { getRules } from "../api.js";

function SeverityBadge({ sev }) {
  const cls = { Critical: "badge-red", High: "badge-red", Medium: "badge-yellow", Low: "badge-blue" }[sev] || "badge-gray";
  return sev ? html`<span class="badge ${cls}" style="margin-left:0.4rem">${sev}</span>` : null;
}

export function AboutPage() {
  const [rules, setRules] = useState([]);

  useEffect(() => { getRules().then(r => setRules(r || [])); }, []);

  return html`
    <div class="container" style="max-width:800px">
      <div class="page-heading">About</div>

      <div class="card mb-2">
        <h2 style="font-size:1.1rem;margin-bottom:0.75rem">What is Malicious PoC Hunter?</h2>
        <p style="color:var(--text-muted);margin-bottom:0.75rem">
          Malicious PoC Hunter automatically scans GitHub for repositories claiming to be
          CVE proof-of-concept exploits. Many threat actors disguise malware as legitimate
          security research to target the security community. This tool detects those
          fake PoCs using YARA static analysis rules.
        </p>
        <p style="color:var(--text-muted)">
          The scanner runs every 30 minutes, fetching newly updated repositories matching
          the <code style="color:var(--accent)">CVE-20** in:name</code> GitHub search query.
          Results, including matched code snippets, are stored and presented here.
        </p>
      </div>

      <div class="card mb-2">
        <h2 style="font-size:1.1rem;margin-bottom:0.75rem">How to Use</h2>
        <ul style="color:var(--text-muted);padding-left:1.25rem;line-height:2">
          <li><strong style="color:var(--text)">Dashboard</strong> – Overview of latest suspicious findings and scan statistics.</li>
          <li><strong style="color:var(--text)">Findings</strong> – Full searchable, filterable list of all scanned repositories.</li>
          <li><strong style="color:var(--text)">Finding Detail</strong> – Code snippet with highlighted YARA matches, community votes and comments.</li>
          <li><strong style="color:var(--text)">Scan History</strong> – Log of every automated scan run.</li>
          <li><strong style="color:var(--text)">Voting & Comments</strong> – Log in with GitHub to confirm or dispute findings.</li>
        </ul>
      </div>

      <div class="card">
        <h2 style="font-size:1.1rem;margin-bottom:0.75rem">Active YARA Rules (${rules.length})</h2>
        ${rules.length === 0 && html`<div class="loading">Loading rules…</div>`}
        ${rules.map(r => html`
          <div class="rule-card card" style="margin-bottom:0.75rem">
            <div class="flex items-center gap-1" style="margin-bottom:0.25rem">
              <h3>${r.name}</h3>
              ${r.category && html`<span class="badge badge-blue">${r.category}</span>`}
              <${SeverityBadge} sev=${r.severity} />
            </div>
            <p>${r.description || "No description."}</p>
          </div>
        `)}
      </div>

      <div class="card mt-2">
        <h2 style="font-size:1.1rem;margin-bottom:0.75rem">False Positives & Feedback</h2>
        <p style="color:var(--text-muted)">
          Static analysis can produce false positives. If you believe a finding is incorrect,
          please downvote it and leave a comment explaining why. Rule thresholds have been
          carefully calibrated to require code context alongside keywords to minimize noise.
        </p>
      </div>
    </div>
  `;
}
