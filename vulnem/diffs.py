"""PR-diff focus extraction for `--scope-mode diff`.

Turns a unified diff (from a file, or a git repo's base...HEAD range) into
a focus directive: the changed files plus any endpoint-looking paths the
diff touches. The directive NARROWS what the agents look at — it never
widens the enforcement layers (host allowlist, proxy guard, prompt scope
all stay exactly as they are; the focus is an additional instruction).
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILES = 40
MAX_ENDPOINTS = 25

# path-like strings that actually look like HTTP endpoints, not asset paths
_ENDPOINT_RE = re.compile(
    r"(?<![\w.])/(?:api|rest|v\d|graphql|auth|login|logout|admin|user|users|search|upload|health|status|[a-z0-9][\w\-]{1,20})(?:/[\w\-.{}]{0,30})*",
    re.IGNORECASE)
_FILE_SUFFIXES = {
    ".py", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".css", ".scss", ".html",
    ".htm", ".json", ".md", ".txt", ".png", ".jpg", ".svg", ".gif", ".ico",
    ".woff", ".woff2", ".map", ".yml", ".yaml", ".toml", ".lock", ".xml",
    ".sql", ".sh", ".env", ".example",
}


@dataclass
class DiffFocus:
    files: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.files and not self.endpoints


def parse_unified_diff(text: str) -> DiffFocus:
    files: list[str] = []
    endpoint_hits: Counter[str] = Counter()
    for line in text.splitlines():
        if line.startswith(("+++ b/", "--- a/", "+++ ", "--- ")):
            path = line[6:] if line.startswith(("+++ b/", "--- a/")) else line[4:]
            path = path.split("\t")[0].strip()
            if path and path != "/dev/null" and path not in files:
                files.append(path)
        elif line[:1] in "+-":
            for match in _ENDPOINT_RE.findall(line):
                candidate = match.rstrip(".-,;:'\"")
                if Path(candidate).suffix.lower() in _FILE_SUFFIXES:
                    continue
                if len(candidate) > 60:
                    continue
                endpoint_hits[candidate] += 1
    # most-touched endpoints first, then alphabetical for stability
    endpoints = [e for e, _ in sorted(endpoint_hits.items(),
                                      key=lambda kv: (-kv[1], kv[0]))]
    return DiffFocus(files=files[:MAX_FILES], endpoints=endpoints[:MAX_ENDPOINTS])


def load_focus(*, diff_file: str | None = None, source_dir: Path | None = None,
               base: str = "origin/main") -> DiffFocus | None:
    """Collect the diff text from a file, or `git diff base...HEAD` in
    `source_dir` (the checked-out PR). Returns None when nothing usable."""
    if diff_file:
        return parse_unified_diff(Path(diff_file).read_text(encoding="utf-8"))
    if source_dir is not None:
        for ref in (f"{base}...HEAD", base):
            try:
                out = subprocess.run(
                    ["git", "diff", "--no-color", ref],
                    cwd=source_dir, capture_output=True, text=True, timeout=30,
                    check=True,
                )
            except (subprocess.SubprocessError, OSError):
                continue
            if out.stdout.strip():
                return parse_unified_diff(out.stdout)
    return None


def focus_directive(focus: DiffFocus) -> str:
    """The prompt-side narrowing instruction for PR-sized scans."""
    parts = [
        "[SCOPE MODE: diff — PR-sized scan]",
        "This scan focuses ONLY on the surfaces below, extracted from the "
        "pull-request diff. Do NOT spend budget on surfaces outside this "
        "list; the ordinary scope rules still apply unchanged.",
    ]
    if focus.files:
        parts.append("Changed files:\n" + "\n".join(f"- {f}" for f in focus.files))
    if focus.endpoints:
        parts.append("Endpoints touched by the diff (map files to routes "
                     "where relevant):\n" + "\n".join(f"- {e}" for e in focus.endpoints))
    if not focus.files and not focus.endpoints:
        parts.append("(diff contained no recognizable files or endpoints — "
                     "treat as a normal full scan)")
    return "\n".join(parts)
