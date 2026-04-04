import { html, useEffect, useRef } from "../app.js";

const LANG_MAP = {
  python: "python", py: "python",
  powershell: "powershell", ps1: "powershell",
  bash: "bash", sh: "bash",
  javascript: "javascript", js: "javascript",
  plaintext: "plaintext",
};

/**
 * Props:
 *   code          {string}  raw code text
 *   language      {string}  language hint (python, bash, powershell, …)
 *   startLine     {number}  1-based first line number (for display)
 *   highlights    {Array}   [{line, col_start, col_end}] snippet-relative, 1-based line
 *   ruleName      {string}  shown in tooltip on highlighted matches
 */
export function CodeBlock({ code, language = "plaintext", startLine = 1, highlights = [], ruleName = "" }) {
  const preRef = useRef(null);

  useEffect(() => {
    if (!preRef.current || !window.Prism) return;
    const el = preRef.current.querySelector("code");
    if (!el) return;

    const lang = LANG_MAP[language] || "plaintext";
    el.className = `language-${lang}`;

    // Reset to raw text, then highlight
    el.textContent = code || "";
    window.Prism.highlightElement(el);

    // Apply YARA match highlights AFTER Prism has run
    if (highlights && highlights.length > 0) {
      applyHighlights(el, highlights, ruleName);
    }
  }, [code, language, highlights]);

  const prismLang = LANG_MAP[language] || "plaintext";

  return html`
    <div class="code-wrap">
      <div class="code-header">
        <span>${language || "text"}</span>
        <span class="text-muted">line ${startLine}</span>
      </div>
      <pre ref=${preRef} class="language-${prismLang}" style="tab-size:4">
        <code class="language-${prismLang}"></code>
      </pre>
    </div>
  `;
}

/**
 * Walk the Prism-highlighted DOM and wrap character ranges in <mark> elements.
 * We convert the flat char-offset positions into DOM ranges.
 */
function applyHighlights(codeEl, highlights, ruleName) {
  // Build a flat text → position map in the highlighted DOM
  const treeWalker = document.createTreeWalker(codeEl, NodeFilter.SHOW_TEXT);
  const textNodes = [];
  let node;
  while ((node = treeWalker.nextNode())) textNodes.push(node);

  // Map line number → character indices within codeEl's textContent
  const fullText = codeEl.textContent;
  const lineOffsets = [0]; // lineOffsets[i] = char index of start of line i+1
  for (let i = 0; i < fullText.length; i++) {
    if (fullText[i] === "\n") lineOffsets.push(i + 1);
  }

  for (const hl of highlights) {
    const lineIdx = (hl.line || 1) - 1; // convert to 0-based
    if (lineIdx < 0 || lineIdx >= lineOffsets.length) continue;
    const charStart = lineOffsets[lineIdx] + (hl.col_start || 0);
    const charEnd   = lineOffsets[lineIdx] + (hl.col_end   || hl.col_start + 1);

    wrapRange(codeEl, textNodes, charStart, charEnd, ruleName);
  }
}

function wrapRange(root, textNodes, start, end, title) {
  let pos = 0;
  for (const tn of textNodes) {
    const len = tn.nodeValue.length;
    const nodeStart = pos;
    const nodeEnd   = pos + len;

    if (nodeEnd <= start || nodeStart >= end) { pos = nodeEnd; continue; }

    const relStart = Math.max(0, start - nodeStart);
    const relEnd   = Math.min(len, end - nodeStart);

    const before = tn.nodeValue.slice(0, relStart);
    const match  = tn.nodeValue.slice(relStart, relEnd);
    const after  = tn.nodeValue.slice(relEnd);

    const mark = document.createElement("mark");
    mark.className = "yara-match";
    mark.title = title || "YARA match";
    mark.textContent = match;

    const parent = tn.parentNode;
    if (before) parent.insertBefore(document.createTextNode(before), tn);
    parent.insertBefore(mark, tn);
    if (after) parent.insertBefore(document.createTextNode(after), tn);
    parent.removeChild(tn);

    break; // only first occurrence per highlight entry
  }
}
