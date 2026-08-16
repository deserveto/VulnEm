"""Minimal .env editor for the setup wizard.

Reading matches :func:`vulnem.config._load_dotenv` exactly: KEY=VALUE lines,
``#`` comments, surrounding quotes stripped, later duplicate keys win
(os.environ semantics). Editing (:func:`upsert_env`) preserves unrelated
lines, comments, blank lines and order; an updated key rewrites its first
occurrence in place and later duplicates are dropped; missing keys append at
the end. The write is atomic-ish (temp file + :func:`os.replace`), and values
are write-only as far as this package is concerned — they are never logged
or echoed back by callers.
"""

from __future__ import annotations

import os
from pathlib import Path

_NEW_FILE_HEADER = "# VulnEm .env — managed by the setup wizard; edit freely\n"


def read_env(path: Path) -> dict[str, str]:
    """Parse ``path`` with config._load_dotenv semantics; later keys win."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key:
            values[key] = value
    return values


def upsert_env(path: Path, updates: dict[str, str]) -> None:
    """Merge ``updates`` into the .env at ``path`` (see module docstring)."""
    existed = path.is_file()
    lines = path.read_text(encoding="utf-8").splitlines() if existed else []
    pending = dict(updates)
    written: set[str] = set()
    out: list[str] = []
    for line in lines:
        key = _key_of(line)
        if key is not None and key in pending:
            if key in written:  # later duplicate of an updated key: drop it
                continue
            written.add(key)
            out.append(f"{key}={pending[key]}")
        else:
            out.append(line)  # untouched line: keep verbatim (comments, blanks)
    out.extend(f"{key}={value}" for key, value in updates.items()
               if key not in written)
    if not existed:
        out.insert(0, _NEW_FILE_HEADER)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def _key_of(line: str) -> str | None:
    """The env-var name a line assigns, or None (comment/blank/no ``=``)."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    return stripped.partition("=")[0].strip() or None
