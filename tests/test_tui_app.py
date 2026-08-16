"""Headless pilot test: the Textual app boots on a run dir and renders the
agent graph, stream, and findings panel (instant replay + pacing/pause)."""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from conftest import FIXTURE_RUN
from textual.widgets import DataTable, RichLog, Tree

from vulnem.ui.tui import VulnEmApp


@pytest.mark.asyncio
async def test_tui_replays_recorded_run() -> None:
    app = VulnEmApp(FIXTURE_RUN, speed=0)  # instant replay
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.5)  # let the 0.1s playback timer fire
        # instant replay: everything applied on the first tick
        assert not app._pending
        assert app.state.events_seen >= 60
        assert "juice-shop" in app.title
        tree = app.query_one("#agents-tree", Tree)
        assert tree.root.children, "agent graph is empty"
        log = app.query_one("#stream", RichLog)
        assert len(log.lines) > 10
        table = app.query_one("#findings-table", DataTable)
        assert table.row_count == len(app.state.findings)
        assert table.row_count == 2
        # stats mention proxy traffic (Phase 3 events are rendered)
        stats = app.query_one("#stats")
        rendered = str(getattr(stats, "visual", "") or stats.content or "")
        assert "flows" in rendered


@pytest.mark.asyncio
async def test_tui_paced_replay_and_pause() -> None:
    app = VulnEmApp(FIXTURE_RUN, speed=2)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.5)
        assert app.state.events_seen > 0
        app.action_toggle_pause()  # bound to <space> in BINDINGS
        assert app._paused
        seen = app.state.events_seen
        await pilot.pause(0.3)
        assert app.state.events_seen == seen, "paused replay must not advance"
        app.action_toggle_follow()
        assert app._follow
