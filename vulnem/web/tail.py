"""Transcript tailing helpers for the web UI.

Byte-offset binary reads (never text mode) so Windows newline translation
cannot desync the offset, and a torn trailing line survives until its
newline arrives — same pattern the TUI uses, reimplemented here so it is
independently testable.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

SCAN_END_TAIL_WINDOW = 8192  # bytes of transcript tail to inspect for scan_end


def read_complete_lines(path: Path, offset: int) -> tuple[list[dict], int]:
    """Read new complete JSON lines from ``path`` starting at byte ``offset``.

    Returns ``(events, new_offset)``. A torn trailing line (no newline yet,
    or not yet valid JSON) stays unread — its bytes are rewound out of the
    returned offset so the next poll picks it up whole. Malformed complete
    lines are skipped.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return [], offset
    if size <= offset:
        return [], offset
    with open(path, "rb") as fh:
        fh.seek(offset)
        chunk = fh.read()
    new_offset = offset + len(chunk)
    last_nl = chunk.rfind(b"\n")
    if last_nl == -1:
        return [], offset  # no complete line yet; leave the bytes for later
    new_offset -= len(chunk) - (last_nl + 1)
    events: list[dict] = []
    for line in chunk[: last_nl + 1].splitlines():
        if not line.strip():
            continue
        with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
            events.append(json.loads(line.decode("utf-8")))
    return events, new_offset


def has_scan_end(path: Path) -> bool:
    """Cheap check whether the transcript already contains a scan_end event.

    Only the last ~8KB is inspected: scan_end is always the final event, so
    scanning the tail bytes for the serialized marker is sufficient without
    loading a large transcript into memory.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return False
    with open(path, "rb") as fh:
        if size > SCAN_END_TAIL_WINDOW:
            fh.seek(size - SCAN_END_TAIL_WINDOW)
        tail = fh.read()
    needle = b'"type": "scan_end"'
    if needle in tail or b'"type":"scan_end"' in tail:
        return True
    # Fallback: parse complete lines in the window (covers odd spacing/key order
    # when the substring form misses but the event is still there).
    for line in tail.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
            if json.loads(line.decode("utf-8")).get("type") == "scan_end":
                return True
    return False


def run_status(run_dir: Path) -> str:
    """Coarse run state: "done" (report written), "running", or "incomplete"."""
    if (run_dir / "findings.json").is_file():
        return "done"
    if (run_dir / "transcript.jsonl").is_file():
        return "running"
    return "incomplete"
