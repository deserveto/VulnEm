"""Textual TUI: live agent graph, tool stream, and findings over a run.

Two modes over the same code path:

- replay (default): render a recorded ``runs/<id>/transcript.jsonl`` at a
  comfortable pace (``--speed`` events/sec, 0 = instant) — no LLM, no Docker.
- follow (``--follow``): keep tailing the transcript after catch-up, so an
  actively running scan can be watched live.

The heavy lifting is ``vulnem/ui/state.py`` (pure reducer); this module only
renders it and paces ingestion.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, RichLog, Static, Tree

from vulnem.ui.state import (
    RunState,
    StreamItem,
    _iter_events,
    replay_speed_for,
)

STATUS_STYLES = {
    "pending": "dim",
    "running": "bold green",
    "waiting": "yellow",
    "completed": "bright_green",
    "stopped": "cyan",
    "crashed": "bold red",
    "failed": "bold red",
}
TONE_STYLES = {
    "text": "dim",
    "tool": "cyan",
    "finding": "bold",
    "agent": "green",
    "msg": "magenta",
    "warn": "bold yellow",
    "sys": "blue",
    "critical": "bold red",
    "info": "cyan",
}
SEVERITY_STYLES = {"critical": "bold red", "high": "red", "medium": "yellow",
                   "low": "cyan", "info": "dim"}
TICK = 0.1  # seconds between playback ticks


class VulnEmApp(App[None]):
    TITLE = "VulnEm"

    CSS = """
    #body { height: 1fr; }
    #left { width: 34; min-width: 26; border: round $primary; padding: 0 1; }
    #right { width: 1fr; }
    #agents-tree { height: 1fr; padding: 0; background: $surface; border: none; }
    #stats { height: auto; border-top: solid $primary; padding: 1 0 0 0; }
    #stream { height: 2fr; border: round $primary; padding: 0 1; }
    #findings { height: 1fr; border: round $primary; }
    #findings-label { padding: 0 1; background: $surface; color: $text; dock: top; }
    """

    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [
        ("q", "quit", "Quit"),
        ("space", "toggle_pause", "Pause/Resume"),
        ("f", "toggle_follow", "Follow live"),
    ]

    def __init__(self, run_dir: Path, *, speed: int | None = None,
                 follow: bool = False) -> None:
        super().__init__()
        self.run_dir = run_dir
        self.transcript_path = run_dir / "transcript.jsonl"
        if not self.transcript_path.is_file():
            raise FileNotFoundError(f"no transcript.jsonl in {run_dir}")
        self.state = RunState()
        self._pending: list[dict] = []
        self._file_offset = 0
        self._speed: int = 0  # resolved at mount (0 = instant)
        self._speed_arg = speed
        self._follow = follow
        self._paused = False
        self._dirty_agents = True
        self._dirty_findings = 0
        self._last_stream_len = 0
        self._finished_replay = False

    # -- layout ----------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="left"):
                yield Tree("Agents", id="agents-tree")
                yield Static("", id="stats")
            with Vertical(id="right"):
                yield RichLog(id="stream", markup=True, wrap=True, highlight=False,
                              max_lines=3000)
                with Vertical(id="findings"):
                    yield Static("Findings", id="findings-label")
                    yield DataTable(id="findings-table", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Sev", "Finding", "URL", "By", "Turn")
        # Pre-read whatever exists now; the timer drains it at `speed`.
        self._pending = list(_iter_events(self.transcript_path))
        self._file_offset = self.transcript_path.stat().st_size
        if self._speed_arg is None:
            done = any(e.get("type") == "scan_end" for e in self._pending)
            self._speed = replay_speed_for(len(self._pending)) if done else 10**9
        else:
            self._speed = self._speed_arg
        self.set_interval(TICK, self._tick)

    # -- playback ----------------------------------------------------------------

    def _read_new_events(self) -> None:
        """Tail the transcript at a byte offset (binary, so Windows newline
        translation can't desync the offset). A torn trailing line is left
        for the next poll."""
        size = self.transcript_path.stat().st_size
        if size <= self._file_offset:
            return
        with open(self.transcript_path, "rb") as fh:
            fh.seek(self._file_offset)
            chunk = fh.read()
        self._file_offset += len(chunk)
        last_nl = chunk.rfind(b"\n")
        if last_nl == -1:
            return  # no complete line yet
        self._file_offset -= len(chunk) - (last_nl + 1)
        for line in chunk[: last_nl + 1].splitlines():
            if not line.strip():
                continue
            with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
                self._pending.append(json.loads(line.decode("utf-8")))

    def _tick(self) -> None:
        if self._paused:
            return
        if self._speed == 0:
            batch = self._pending
            self._pending = []
        else:
            take = max(1, int(self._speed * TICK))
            batch, self._pending = self._pending[:take], self._pending[take:]
        if batch:
            self.state.apply_all(batch)
            self._dirty_agents = True
        elif self._follow:
            self._read_new_events()
        self._render()

    # -- rendering ----------------------------------------------------------------

    def _render(self) -> None:
        self._render_header()
        if self._dirty_agents:
            self._render_agents()
            self._render_stats()
            self._dirty_agents = False
        if len(self.state.findings) != self._dirty_findings:
            self._render_findings()
            self._dirty_findings = len(self.state.findings)
        self._render_stream()

    def _render_header(self) -> None:
        s = self.state
        title = f"VulnEm — {s.target or self.run_dir.name}"
        meta = s.model or "?"
        self.title = title
        self.sub_title = meta

    def _render_agents(self) -> None:
        tree = self.query_one("#agents-tree", Tree)
        tree.clear()
        roots = [a for a in self.state.agents.values() if a.parent_id is None]
        children: dict[str, list] = {}
        for a in self.state.agents.values():
            if a.parent_id is not None:
                children.setdefault(a.parent_id, []).append(a)

        def add(node, view):
            style = STATUS_STYLES.get(view.status, "white")
            label = f"[{style}]{view.name}[/{style}] [dim]{view.status}[/dim]"
            if view.findings:
                label += f" [red]({view.findings}f)[/red]"
            child = node.add(label)
            for sub in sorted(children.get(view.agent_id, []),
                              key=lambda v: v.name):
                add(child, sub)
            child.expand()

        for view in sorted(roots, key=lambda v: (v.role != "root", v.name)):
            add(tree.root, view)
        tree.root.expand()

    def _render_stats(self) -> None:
        s = self.state
        counts = s.severity_counts()
        sev_parts = " ".join(
            f"[{SEVERITY_STYLES.get(sev, 'white')}]{sev[:4]}:{n}[/]"
            for sev, n in sorted(counts.items()))
        lines = [
            f"[dim]target[/dim] {s.target or '—'}",
            f"[dim]turns[/dim] {s.turns_used or sum(a.turns for a in s.agents.values())}"
            f"/{s.budget_turns or '?'}  [dim]tokens[/dim] {s.total_tokens or sum(a.tokens for a in s.agents.values()):,}",
            f"[dim]flows[/dim] {s.flow_count:,}  [dim]blocked[/dim] {s.blocked_count}"
            f"  [dim]shots[/dim] {len(s.screenshots)}",
            f"[dim]findings[/dim] {sev_parts or '—'}",
        ]
        if s.stop_reason:
            style = "bright_green" if s.stop_reason == "finish_tool" else "yellow"
            lines.append(f"[{style}]ended ({s.stop_reason})[/{style}]")
        elif self._pending and not self._follow:
            lines.append("[dim]replaying…[/dim]")
        elif self._follow:
            lines.append("[green]following live…[/green]" if not self._paused
                         else "[yellow]paused[/yellow]")
        self.query_one("#stats", Static).update("\n".join(lines))

    def _render_findings(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        for f in self.state.findings[self._dirty_findings:]:
            table.add_row(
                f"[{SEVERITY_STYLES.get(f.severity, 'white')}]{f.severity[:4].upper()}[/]",
                f.title, f.url or "—", f.by, str(f.turn))
        total = (self.state.findings_total if self.state.findings_total is not None
                 else len(self.state.findings))
        self.query_one("#findings-label", Static).update(
            f"Findings — {len(self.state.findings)} reported"
            + (f", {total} after dedupe" if self.state.findings_total is not None else ""))

    def _render_stream(self) -> None:
        log = self.query_one("#stream", RichLog)
        items: list[StreamItem] = list(self.state.stream)
        for item in items[self._last_stream_len:]:
            agent = f"[blue]│{item.agent}│[/] " if item.agent else ""
            tone = TONE_STYLES.get(item.tone, "white")
            log.write(f"[dim]{item.ts[11:] if item.ts else ''}[/dim] {agent}"
                      f"[{tone}]{item.text}[/{tone}]")
        self._last_stream_len = len(items)

    # -- actions -----------------------------------------------------------------

    def action_toggle_pause(self) -> None:
        self._paused = not self._paused
        self._render_stats()

    def action_toggle_follow(self) -> None:
        self._follow = not self._follow
        self._render_stats()


def run_tui(run_dir: Path, *, speed: int | None = None, follow: bool = False) -> None:
    """Entry point for `vulnem tui <run_dir>`."""
    app = VulnEmApp(run_dir, speed=speed, follow=follow)
    asyncio.run(app.run_async())
