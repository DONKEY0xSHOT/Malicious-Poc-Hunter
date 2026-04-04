import { html, useState, useEffect } from "../app.js";
import { getFinding, voteFinding, postComment, deleteComment } from "../api.js";
import { CodeBlock } from "./code-block.js";
import { navigate } from "../app.js";

function SeverityBadge({ severity }) {
  const cls = { Critical: "badge-red", High: "badge-red", Medium: "badge-yellow", Low: "badge-blue" }[severity] || "badge-gray";
  return severity ? html`<span class="badge ${cls}">${severity}</span>` : null;
}

function CategoryBadge({ category }) {
  return category ? html`<span class="badge badge-blue">${category}</span>` : null;
}

function MatchCard({ match }) {
  const firstMs = match.matched_strings?.[0];
  const highlights = match.matched_strings?.map(ms => ({
    // matched_strings offsets are snippet-relative in our schema
    line: 1, col_start: 0, col_end: ms.length,
  })) || [];

  // Use the stored code_snippet directly
  return html`
    <div class="match-card">
      <div class="match-header">
        <div class="flex items-center gap-1">
          <strong>${match.rule_name}</strong>
          <${CategoryBadge} category=${match.rule_category} />
          <${SeverityBadge} severity=${match.rule_severity} />
        </div>
        <span class="file-path">${match.file_path}</span>
      </div>
      ${match.code_snippet && html`
        <${CodeBlock}
          code=${match.code_snippet}
          language=${detectLang(match.file_path)}
          startLine=${match.snippet_start_line || 1}
          highlights=${[]}
          ruleName=${match.rule_name}
        />
      `}
      ${match.matched_strings?.length > 0 && html`
        <div style="padding:0.5rem 0.75rem;background:var(--bg-elevated);font-size:0.75rem;color:var(--text-muted)">
          ${match.matched_strings.map(ms => html`
            <span style="margin-right:0.75rem">
              <code style="color:var(--accent)">${ms.identifier}</code>
              ${" "}@ offset ${ms.offset}:
              ${" "}<code style="color:var(--warning)">${ms.data_preview}</code>
            </span>
          `)}
        </div>
      `}
    </div>
  `;
}

function VoteControls({ votes, onVote, user }) {
  const { score = 0, user_vote = null } = votes || {};
  return html`
    <div class="vote-controls">
      <button
        class="vote-btn ${user_vote === 1 ? "active-up" : ""}"
        onClick=${() => onVote(1)}
        title=${user ? "Upvote" : "Login to vote"}
        disabled=${!user}
      >▲</button>
      <span class="vote-score" style="color:${score > 0 ? "var(--success)" : score < 0 ? "var(--danger)" : "var(--text-muted)"}">${score}</span>
      <button
        class="vote-btn ${user_vote === -1 ? "active-down" : ""}"
        onClick=${() => onVote(-1)}
        title=${user ? "Downvote" : "Login to vote"}
        disabled=${!user}
      >▼</button>
      ${!user && html`<span class="text-muted" style="font-size:0.8rem">Log in to vote</span>`}
    </div>
  `;
}

function Comment({ comment, currentUser, onDelete }) {
  return html`
    <div class="comment">
      <img
        src="${comment.github_avatar_url || ""}"
        alt="${comment.github_user}"
        class="comment-avatar"
        onError=${e => { e.target.src = ""; }}
      />
      <div class="comment-body-wrap" style="flex:1">
        <div class="meta">
          <strong>${comment.github_user}</strong>
          ${" · "}
          <span>${new Date(comment.created_at).toLocaleString()}</span>
          ${currentUser?.github_user === comment.github_user && html`
            <button class="btn btn-ghost btn-sm" style="margin-left:0.5rem" onClick=${() => onDelete(comment.id)}>
              Delete
            </button>
          `}
        </div>
        <p style="white-space:pre-wrap">${comment.body}</p>
      </div>
    </div>
  `;
}

function CommentsSection({ findingId, comments: initial, user }) {
  const [comments, setComments]   = useState(initial || []);
  const [draft, setDraft]         = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async () => {
    if (!draft.trim()) return;
    setSubmitting(true);
    try {
      const c = await postComment(findingId, draft.trim());
      if (c) { setComments(prev => [...prev, c]); setDraft(""); }
    } finally { setSubmitting(false); }
  };

  const handleDelete = async (cid) => {
    const ok = await deleteComment(findingId, cid);
    if (ok !== undefined) setComments(prev => prev.filter(c => c.id !== cid));
  };

  return html`
    <div class="comments-section">
      <h3>Comments (${comments.length})</h3>
      ${comments.map(c => html`
        <${Comment} comment=${c} currentUser=${user} onDelete=${handleDelete} />
      `)}
      ${user
        ? html`
            <div class="comment-form mt-2">
              <textarea
                rows="3"
                placeholder="Leave a comment…"
                value=${draft}
                onInput=${e => setDraft(e.target.value)}
                maxLength="2000"
              ></textarea>
              <div class="flex items-center gap-1 mt-1">
                <button
                  class="btn btn-primary btn-sm"
                  disabled=${submitting || !draft.trim()}
                  onClick=${handleSubmit}
                >${submitting ? "Posting…" : "Post comment"}</button>
                <span class="text-muted" style="font-size:0.8rem">${draft.length}/2000</span>
              </div>
            </div>
          `
        : html`<p class="text-muted mt-2" style="font-size:0.875rem">
            <a href="/api/v1/auth/github">Log in with GitHub</a> to comment.
          </p>`
      }
    </div>
  `;
}

export function FindingDetailPage({ id, user }) {
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    setLoading(true);
    getFinding(id)
      .then(f => { setFinding(f); setLoading(false); })
      .catch(e => { if (e.status === 404) setNotFound(true); setLoading(false); });
  }, [id]);

  if (loading) return html`<div class="container loading">Loading…</div>`;
  if (notFound || !finding) return html`<div class="container error-msg">Finding not found.</div>`;

  const handleVote = async (vote) => {
    const result = await voteFinding(finding.id, vote);
    if (result) setFinding(prev => ({ ...prev, votes: result }));
  };

  return html`
    <div class="container">
      <a href="/findings" onClick=${e => { e.preventDefault(); navigate("/findings"); }} class="text-muted" style="font-size:0.875rem">
        ← Back to Findings
      </a>

      <div class="repo-header mt-2">
        <h1>${finding.repo_full_name}</h1>
        <div class="repo-meta">
          <a href="${finding.repo_url}" target="_blank" rel="noopener noreferrer">View on GitHub ↗</a>
          <span>⭐ ${finding.repo_stars} stars</span>
          <span>${finding.repo_size_kb}KB</span>
          <span>Branch: ${finding.default_branch}</span>
          <span>Scanned: ${new Date(finding.scanned_at).toLocaleString()}</span>
        </div>
        ${finding.repo_description && html`<p class="text-muted mt-1">${finding.repo_description}</p>`}
      </div>

      <div class="mt-2">
        <strong>YARA Matches (${finding.matches?.length || 0})</strong>
        ${finding.matches?.map(m => html`<${MatchCard} match=${m} />`)}
        ${(!finding.matches || finding.matches.length === 0) && html`
          <div class="text-muted" style="padding:1rem 0">No matches recorded.</div>
        `}
      </div>

      <hr style="border-color:var(--border);margin:1.5rem 0" />

      <${VoteControls} votes=${finding.votes} onVote=${handleVote} user=${user} />

      <${CommentsSection}
        findingId=${finding.id}
        comments=${finding.comments}
        user=${user}
      />
    </div>
  `;
}

function detectLang(filePath) {
  const ext = (filePath || "").split(".").pop().toLowerCase();
  return { py:"python", ps1:"powershell", sh:"bash", bash:"bash", js:"javascript", rb:"ruby" }[ext] || "plaintext";
}
