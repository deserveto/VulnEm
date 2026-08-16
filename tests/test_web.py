"""Tests for the read-only web UI (vulnem/web/): tailing, serialization, routes.

Uses the committed fixture run copied into a tmp runs dir — no Docker, no
LLM, no dependency on the dev machine's runs/ directory.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from conftest import FIXTURE_RUN

from vulnem.config import Settings
from vulnem.ui.state import RunState
from vulnem.web.app import create_app
from vulnem.web.serialize import state_snapshot
from vulnem.web.tail import has_scan_end, read_complete_lines, run_status

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

RUN_ID = "20260816-120000-juice-shop-fix1"


@pytest.fixture()
def runs_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / RUN_ID
    shutil.copytree(FIXTURE_RUN, run_dir)
    shots = run_dir / "artifacts" / "client-side-xss"
    shots.mkdir(parents=True)
    (shots / "shot1.png").write_bytes(b"\x89PNG fake screenshot")
    return tmp_path


@pytest.fixture()
def client(runs_dir: Path) -> TestClient:
    settings = Settings(runs_dir=runs_dir, skills_dir=runs_dir / "skills")
    return TestClient(create_app(settings))


# -- runs list -----------------------------------------------------------------


def test_runs_list(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert RUN_ID in resp.text
    assert "juice-shop" in resp.text
    assert 'status-done' in resp.text


def test_runs_list_empty_state(tmp_path: Path) -> None:
    settings = Settings(runs_dir=tmp_path / "runs", skills_dir=tmp_path)
    resp = TestClient(create_app(settings)).get("/")
    assert resp.status_code == 200
    assert "No runs yet" in resp.text


# -- run page + SSE --------------------------------------------------------------


def test_run_page(client: TestClient) -> None:
    resp = client.get(f"/runs/{RUN_ID}")
    assert resp.status_code == 200
    assert "juice-shop" in resp.text
    assert 'id="bootstrap"' in resp.text
    assert "/static/run.js" in resp.text
    assert f"/runs/{RUN_ID}/events" in resp.text


def test_sse_finished_run_sends_snap_then_end(client: TestClient) -> None:
    resp = client.get(f"/runs/{RUN_ID}/events")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert "event: snap" in resp.text
    assert "event: end" in resp.text
    assert '"target"' in resp.text
    # snap comes before end
    assert resp.text.index("event: snap") < resp.text.index("event: end")


def test_sse_live_run_tails_until_scan_end(runs_dir: Path) -> None:
    """A running scan's transcript has no scan_end yet: the stream sends snap,
    then a delta carrying only the newly appended events, then end once the
    scan_end line lands."""
    import threading
    import time

    transcript = runs_dir / RUN_ID / "transcript.jsonl"
    # Strip the fixture's final scan_end -> a genuinely "live" transcript.
    lines = transcript.read_bytes().splitlines(keepends=True)
    live = [ln for ln in lines if b'"scan_end"' not in ln]
    transcript.write_bytes(b"".join(live))
    end_line = json.dumps({"type": "scan_end", "stop_reason": "finish_tool",
                           "turns_used": 9, "total_tokens": 1, "findings": 2})

    def append_end() -> None:
        time.sleep(0.2)
        with open(transcript, "ab") as fh:  # binary append, newline-terminated
            fh.write((end_line + "\n").encode())

    settings = Settings(runs_dir=runs_dir, skills_dir=runs_dir / "skills")
    (runs_dir / RUN_ID / "findings.json").unlink()  # keep the run "live"
    thread = threading.Thread(target=append_end)
    thread.start()
    try:
        resp = TestClient(create_app(settings)).get(f"/runs/{RUN_ID}/events")
    finally:
        thread.join()
    assert resp.status_code == 200
    snap, *rest = resp.text.split("event: delta")
    assert "event: snap" in snap
    assert len(rest) == 1
    assert '"finish_tool"' in rest[0]  # the new event's stream line
    assert 'event: end\ndata: {"status":"done"}' in resp.text


def test_run_page_missing_run_404(client: TestClient) -> None:
    assert client.get("/runs/20990101-000000-nope-abcd").status_code == 404


# -- report page -----------------------------------------------------------------


def test_report_page(client: TestClient) -> None:
    data = json.loads((FIXTURE_RUN / "findings.json").read_text(encoding="utf-8"))
    title = data["findings"][0]["title"]
    resp = client.get(f"/runs/{RUN_ID}/report")
    assert resp.status_code == 200
    assert title in resp.text
    # PoC body survives (quotes are HTML-escaped; plain substrings must not be)
    assert "orange%27" in resp.text
    assert "rest/products/search" in resp.text


def test_report_page_without_findings_404(runs_dir: Path) -> None:
    (runs_dir / RUN_ID / "findings.json").unlink()
    settings = Settings(runs_dir=runs_dir, skills_dir=runs_dir / "skills")
    resp = TestClient(create_app(settings)).get(f"/runs/{RUN_ID}/report")
    assert resp.status_code == 404
    assert "not finished" in resp.text


# -- file whitelist + traversal -----------------------------------------------------


def test_file_route_whitelist(client: TestClient) -> None:
    resp = client.get(f"/runs/{RUN_ID}/file/report.md")
    assert resp.status_code == 200
    assert resp.content  # fixture report.md is non-empty
    assert client.get(f"/runs/{RUN_ID}/file/config.json").status_code == 200


def test_file_route_rejects_traversal_and_unknown(client: TestClient) -> None:
    for name in ("..%2fconfig.json", "..%2f..%2fpyproject.toml", "secret.txt",
                 "state.json", ".env"):  # anything off the whitelist
        assert client.get(f"/runs/{RUN_ID}/file/{name}").status_code == 404, name
    # whitelisted but absent from the fixture run -> still 404
    assert client.get(f"/runs/{RUN_ID}/file/report.pdf").status_code == 404


def test_artifacts_route(client: TestClient) -> None:
    resp = client.get(f"/runs/{RUN_ID}/artifacts/client-side-xss/shot1.png")
    assert resp.status_code == 200
    assert resp.content.startswith(b"\x89PNG")
    assert client.get(f"/runs/{RUN_ID}/artifacts/..%2fconfig.json").status_code == 404
    assert client.get(f"/runs/{RUN_ID}/artifacts/nope.png").status_code == 404


def test_run_id_traversal_404(client: TestClient) -> None:
    # %2f variants stay one path segment server-side (httpx normalizes raw "..")
    assert client.get("/runs/..%2fpyproject").status_code == 404
    assert client.get("/runs/..%2e").status_code == 404
    assert client.get("/runs/aa%2f..%2fpyproject.toml").status_code == 404


# -- tail helpers (unit) --------------------------------------------------------------


def test_read_complete_lines_tolerates_torn_tail(tmp_path: Path) -> None:
    path = tmp_path / "transcript.jsonl"
    line1 = json.dumps({"type": "scan_start", "target": "http://x"})
    line2 = json.dumps({"type": "agent_start"})
    torn = '{"type": "scan_end", "stop_r'  # no newline yet
    path.write_bytes(f"{line1}\n{line2}\n{torn}".encode())

    events, offset = read_complete_lines(path, 0)
    assert [e["type"] for e in events] == ["scan_start", "agent_start"]
    assert offset == len(f"{line1}\n{line2}\n".encode())  # torn bytes left behind

    rest = 'eason": "finish_tool"}\n' + json.dumps({"type": "unknown"}) + "\n"
    with open(path, "ab") as fh:
        fh.write(rest.encode())
    events, offset = read_complete_lines(path, offset)
    assert [e["type"] for e in events] == ["scan_end", "unknown"]
    assert offset == path.stat().st_size

    events, offset = read_complete_lines(path, offset)  # nothing new
    assert events == [] and offset == path.stat().st_size


def test_read_complete_lines_skips_bad_json(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_bytes(b'{"type": "a"}\nnot json\n{"type": "b"}\n')
    events, offset = read_complete_lines(path, 0)
    assert [e["type"] for e in events] == ["a", "b"]
    assert offset == path.stat().st_size


def test_has_scan_end_and_run_status(tmp_path: Path, runs_dir: Path) -> None:
    transcript = FIXTURE_RUN / "transcript.jsonl"
    assert has_scan_end(transcript) is True
    assert run_status(runs_dir / RUN_ID) == "done"

    live = tmp_path / "live-run"
    live.mkdir()
    (live / "transcript.jsonl").write_bytes(
        b'{"type": "scan_start"}\n{"type": "tool_call"}\n')
    assert has_scan_end(live / "transcript.jsonl") is False
    assert run_status(live) == "running"

    empty = tmp_path / "empty-run"
    empty.mkdir()
    assert run_status(empty) == "incomplete"


# -- serialization (unit) ----------------------------------------------------------------


def test_state_snapshot_shape_and_stream_cap() -> None:
    state = RunState.from_transcript(FIXTURE_RUN / "transcript.jsonl")
    full = state_snapshot(state)
    assert full["meta"]["target"] == "http://juice-shop:3000"
    assert len(full["agents"]) == 3
    assert len(full["findings"]) == 2
    assert full["severity"]["high"] == 2
    assert len(full["stream"]) == min(400, len(state.stream))

    capped = state_snapshot(state, stream_tail=10)
    assert len(capped["stream"]) == 10
    assert capped["stream_total"] == len(state.stream)
    assert capped["stream"][-1] == full["stream"][-1]  # same tail item
    item = capped["stream"][0]
    assert set(item) == {"ts", "agent", "tone", "text"}
