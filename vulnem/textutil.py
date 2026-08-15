"""Small text helpers shared across tool modules (kept import-cycle-free)."""

from __future__ import annotations

from vulnem.config import OUTPUT_TRUNCATE_CHARS


def truncate(text: str, limit: int = OUTPUT_TRUNCATE_CHARS) -> str:
    """Keep head and tail of long tool output so the model sees both."""
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-(limit // 2) :]
    omitted = len(text) - limit
    return f"{head}\n... [{omitted} chars truncated] ...\n{tail}"
