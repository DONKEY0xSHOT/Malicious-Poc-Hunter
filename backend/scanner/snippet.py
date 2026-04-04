"""Extract human-readable code snippets around YARA match offsets."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_CONTEXT_LINES = 10
_MAX_SNIPPET_CHARS = 4000  # safety cap before storing in DB


@dataclass
class HighlightRange:
    line: int       # 1-based, relative to snippet start
    col_start: int  # 0-based character index in that line
    col_end: int    # exclusive


@dataclass
class SnippetResult:
    code: str = ""
    start_line: int = 1
    highlights: list[HighlightRange] = field(default_factory=list)
    language: str = ""


def extract_snippet(
    file_path: str,
    byte_offset: int,
    match_length: int,
    context_lines: int = _CONTEXT_LINES,
) -> SnippetResult:
    """Return a SnippetResult centred on the YARA match at *byte_offset*.

    All positions returned are relative to the snippet (not the full file).
    """
    try:
        raw = Path_read_bytes(file_path)
    except OSError as exc:
        logger.debug("Cannot read %s for snippet: %s", file_path, exc)
        return SnippetResult()

    # Detect likely binary file
    if b"\x00" in raw[:512]:
        return SnippetResult(code="[binary file – snippet not available]")

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return SnippetResult(code="[encoding error – snippet not available]")

    lines = text.splitlines(keepends=True)
    if not lines:
        return SnippetResult()

    # Find 1-based line number of the match byte offset
    match_line = _byte_offset_to_line(raw, byte_offset)

    # Window: [start_line, end_line] inclusive, 1-based
    start_line = max(1, match_line - context_lines)
    end_line = min(len(lines), match_line + context_lines)

    snippet_lines = lines[start_line - 1 : end_line]
    code = "".join(snippet_lines)
    if len(code) > _MAX_SNIPPET_CHARS:
        code = code[:_MAX_SNIPPET_CHARS] + "\n… (truncated)"

    # Compute highlight position relative to snippet
    highlights: list[HighlightRange] = []
    try:
        snippet_start_byte = _line_start_byte(raw, start_line)
        rel_offset = byte_offset - snippet_start_byte
        if 0 <= rel_offset < len(code.encode("utf-8", errors="replace")):
            snippet_text = code
            char_offset = len(raw[snippet_start_byte : snippet_start_byte + rel_offset].decode("utf-8", errors="replace"))
            # Find which line of the snippet the match falls in
            snippet_prefix = snippet_text[:char_offset]
            snippet_lines_before = snippet_prefix.count("\n")
            line_start_idx = snippet_prefix.rfind("\n") + 1
            col_start = char_offset - line_start_idx
            col_end = col_start + match_length
            highlights.append(
                HighlightRange(
                    line=snippet_lines_before + 1,
                    col_start=col_start,
                    col_end=col_end,
                )
            )
    except Exception as exc:
        logger.debug("Highlight computation failed for %s: %s", file_path, exc)

    language = _detect_language(file_path)
    return SnippetResult(
        code=code,
        start_line=start_line,
        highlights=highlights,
        language=language,
    )


# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #

def _byte_offset_to_line(raw: bytes, offset: int) -> int:
    """Return 1-based line number for a byte offset in *raw*."""
    clamped = min(offset, len(raw))
    return raw[:clamped].count(b"\n") + 1


def _line_start_byte(raw: bytes, line_number: int) -> int:
    """Return the byte offset of the start of *line_number* (1-based)."""
    if line_number <= 1:
        return 0
    n = 0
    for idx, b in enumerate(raw):
        if b == ord("\n"):
            n += 1
            if n == line_number - 1:
                return idx + 1
    return len(raw)


def _detect_language(file_path: str) -> str:
    from pathlib import Path as _P
    ext = _P(file_path).suffix.lower()
    return {
        ".py": "python",
        ".ps1": "powershell",
        ".sh": "bash",
        ".bash": "bash",
        ".bat": "batch",
        ".cmd": "batch",
        ".js": "javascript",
        ".ts": "typescript",
        ".rb": "ruby",
        ".php": "php",
        ".vbs": "vbscript",
        ".pl": "perl",
        ".lua": "lua",
        ".go": "go",
        ".cs": "csharp",
        ".java": "java",
    }.get(ext, "plaintext")


def Path_read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()
