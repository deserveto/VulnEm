"""Headless pilot test: the Textual app boots on a recorded run and renders
the agent graph, stream, and findings panel (instant replay)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.widgets import DataTable, RichLog, Tree

from vulnem.ui.tui import VulnEmApp

RUN_DIR = Path(__file__).resolve().parent.parent / "runs" / "20260815-195935-juice-shop-ea92"


@pytest.mark.asyncio
async def test_tui_replays_recorded_run() -> None:
    app = VulnEmApp(RUN_DIR, speed=0)  # instant replay
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.5)  # let the 0.1s playback timer fire
        # instant replay: everything applied on the first tick
        assert not app._pending
        assert app.state.events_seen > 1000
        assert "juice-shop" in app.title
        tree = app.query_one("#agents-tree", Tree)
        assert tree.root.children, "agent graph is empty"
        log = app.query_one("#stream", RichLog)
        assert len(log.lines) > 50
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == len(app.state.findings)
        assert table.row_count >= 1
        # stats mention proxy traffic (Phase 3 events are rendered)
        stats = app.query_one("#stats")
        rendered = str(getattr(stats, "visual", "") or stats.content or "")
        assert "flows" in rendered


@pytest.mark.asyncio
async def test_tui_paced_replay_and_pause() -> None:
    app = VulnEmApp(RUN_DIR, speed=5)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.5)
        assert app._pending, "paced replay should still have backlog"
        assert app.state.events_seen > 0
        app.action_toggle_pause()  # bound to <space> in BINDINGS
        assert app._paused
        seen = app.state.events_seen
        await pilot.pause(0.3)
        assert app.state.events_seen == seen, "paused replay must not advance"
