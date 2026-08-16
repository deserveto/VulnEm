"""Pure serialization of run state for the web UI (no FastAPI imports).

Two shapes: cheap per-run summaries for the runs list (config.json +
findings.json only) and the full view model over a reduced
:class:`~vulnem.ui.state.RunState` for the run page and its SSE deltas.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from vulnem.ui.state import RunState, StreamItem

SEVERITIES = ("critical", "high", "medium", "low", "info")


def run_summary(run_dir: Path) -> dict | None:
    """Cheap listing row for a run dir: config/target/model/status/severity counts.

    Returns None for directories that are neither a run (no config.json) nor
    an in-progress run (no transcript.jsonl).
    """
    config_path = run_dir / "config.json"
    transcript_path = run_dir / "transcript.jsonl"
    if not config_path.is_file() and not transcript_path.is_file():
        return None
    config: dict = {}
    if config_path.is_file():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            config = {}
    findings_path = run_dir / "findings.json"
    counts: dict | None = None
    if findings_path.is_file():
        try:
            data = json.loads(findings_path.read_text(encoding="utf-8"))
            counts = {sev: 0 for sev in SEVERITIES}
            for finding in data.get("findings") or []:
                sev = str(finding.get("severity", "info")).lower()
                counts[sev] = counts.get(sev, 0) + 1
        except (json.JSONDecodeError, OSError):
            counts = None
    return {
        "id": run_dir.name,
        "target": str(config.get("target", "")),
        "model": str(config.get("model", "")),
        "started_at": str(config.get("started_at", "")),
        "status": ("done" if findings_path.is_file()
                   else "running" if transcript_path.is_file() else "incomplete"),
        "findings": counts,
    }


def _meta(state: RunState) -> dict:
    return {
        "target": state.target,
        "model": state.model,
        "mode": state.mode,
        "budget_turns": state.budget_turns,
        "proxy": state.proxy,
        "authenticated": state.authenticated,
        "started_at": state.started_at,
        "ended_at": state.ended_at,
        "stop_reason": state.stop_reason,
        "turns_used": state.turns_used,
        "total_tokens": state.total_tokens,
        "findings_total": (state.findings_total if state.findings_total is not None
                           else len(state.findings)),
        "events_seen": state.events_seen,
        "flow_count": state.flow_count,
        "blocked_count": state.blocked_count,
        "screenshots": len(state.screenshots),
    }


def _agents(state: RunState) -> list[dict]:
    return [asdict(view) for view in state.agents.values()]


def _findings(state: RunState) -> list[dict]:
    return [asdict(f) for f in state.findings]


def _severity(state: RunState) -> dict:
    counts = {sev: 0 for sev in SEVERITIES}
    for f in state.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _stream_items(items: list[StreamItem]) -> list[dict]:
    return [asdict(item) for item in items]


def state_snapshot(state: RunState, stream_tail: int = 400) -> dict:
    """Full view model: meta, agents, findings, severity, blocked, stream tail."""
    return {
        "meta": _meta(state),
        "agents": _agents(state),
        "findings": _findings(state),
        "severity": _severity(state),
        "blocked": list(state.blocked[-20:]),
        "stream": _stream_items(list(state.stream)[-stream_tail:]),
        "stream_total": len(state.stream),
    }


def state_delta(state: RunState, new_items: list[StreamItem]) -> dict:
    """SSE delta payload: only new stream items, everything else re-sent whole
    (cheap, and keeps the client trivial)."""
    return {
        "meta": _meta(state),
        "agents": _agents(state),
        "findings": _findings(state),
        "severity": _severity(state),
        "stream": _stream_items(new_items),
        "stream_total": len(state.stream),
    }
