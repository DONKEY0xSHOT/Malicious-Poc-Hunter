"""YARA rule compilation and file scanning."""
from __future__ import annotations

import logging
import os
from pathlib import Path

import yara

from .models import MatchedString, YaraMatch

logger = logging.getLogger(__name__)

# Only apply the obfuscation rule to code files, not certs/images/docs
_OBFUSCATION_RULE = "Obfuscation_Encoded_Execution"
_CODE_EXTENSIONS = {
    ".py", ".ps1", ".sh", ".bash", ".bat", ".cmd",
    ".js", ".ts", ".rb", ".php", ".vbs", ".hta",
    ".pl", ".lua", ".r", ".go", ".cs", ".java",
}

# Skip binary/media formats entirely
_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".exe", ".dll", ".so", ".dylib", ".lib", ".obj",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".avi", ".mov",
    ".pem", ".crt", ".cer", ".der",  # cert files often contain long base64
}


class YaraEngine:
    def __init__(self, rules_dir: str) -> None:
        rules_path = Path(rules_dir)
        if not rules_path.is_dir():
            raise ValueError(f"Rules directory not found: {rules_dir}")

        filepaths: dict[str, str] = {}
        for fp in rules_path.rglob("*.yar"):
            filepaths[fp.stem] = str(fp)
        for fp in rules_path.rglob("*.yara"):
            filepaths[fp.stem] = str(fp)

        if not filepaths:
            raise ValueError(f"No .yar/.yara files in {rules_dir}")

        try:
            self._rules: yara.Rules = yara.compile(filepaths=filepaths)
        except yara.SyntaxError as exc:
            raise ValueError(f"YARA syntax error: {exc}") from exc

        self._rule_count = len(filepaths)
        logger.info("Compiled %d YARA rule file(s) from %s", self._rule_count, rules_dir)

    @property
    def rule_count(self) -> int:
        return self._rule_count

    def scan_file(self, file_path: str) -> list[YaraMatch]:
        """Scan a single file. Returns list of YaraMatch objects."""
        ext = Path(file_path).suffix.lower()
        try:
            raw_matches: list[yara.Match] = self._rules.match(file_path)
        except yara.Error as exc:
            logger.debug("YARA scan error on %s: %s", file_path, exc)
            return []

        results: list[YaraMatch] = []
        for m in raw_matches:
            # Filter obfuscation rule to code files only
            if m.rule == _OBFUSCATION_RULE and ext not in _CODE_EXTENSIONS:
                continue

            file_size = 0
            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                pass

            matched_strings = []
            for s in m.strings:
                # s is a yara.StringMatch; iterate its instances
                for instance in s.instances:
                    preview = _safe_preview(instance.matched_data)
                    matched_strings.append(
                        MatchedString(
                            identifier=s.identifier,
                            offset=instance.offset,
                            length=len(instance.matched_data),
                            data_preview=preview,
                        )
                    )

            results.append(
                YaraMatch(
                    rule_name=m.rule,
                    rule_category=m.meta.get("category"),
                    rule_severity=m.meta.get("severity"),
                    file_path=file_path,
                    file_size=file_size,
                    matched_strings=matched_strings,
                )
            )

        return results

    def scan_directory(
        self,
        dir_path: str,
        max_file_size: int = 10 * 1024 * 1024,
    ) -> list[tuple[str, YaraMatch]]:
        """Walk a directory and scan all scannable files.

        Returns list of (relative_path, YaraMatch) tuples.
        """
        results: list[tuple[str, YaraMatch]] = []
        base = Path(dir_path)

        for root, _dirs, files in os.walk(dir_path):
            for fname in files:
                fp = Path(root) / fname
                ext = fp.suffix.lower()

                if ext in _BINARY_EXTENSIONS:
                    continue
                try:
                    if fp.stat().st_size > max_file_size:
                        continue
                except OSError:
                    continue

                matches = self.scan_file(str(fp))
                rel = str(fp.relative_to(base))
                for match in matches:
                    results.append((rel, match))

        return results

    def get_rule_info(self) -> list[dict]:
        """Return metadata for all compiled rules."""
        info: list[dict] = []
        # Scan an empty byte string to enumerate rule names + meta
        for m in self._rules.match(data=b"__probe__that_never_matches__"):
            info.append(
                {
                    "name": m.rule,
                    "category": m.meta.get("category"),
                    "severity": m.meta.get("severity"),
                    "description": m.meta.get("description"),
                }
            )
        return info


def _safe_preview(data: bytes, max_len: int = 80) -> str:
    """Convert raw matched bytes to a human-readable preview."""
    try:
        return data[:max_len].decode("utf-8", errors="replace")
    except Exception:
        return data[:max_len].hex()
