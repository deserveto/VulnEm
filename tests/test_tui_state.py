"""Tests for the TUI's transcript reducer (vulnem/ui/state.py)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnem.ui.state import RunState, format_tool_call, replay_speed_for


def _events(run_dir: str) -> list[dict]:
    path = Path(__file__).resolve().parent.parent / "runs" / run_dir / "transcript.jsonl"
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln]


def test_reducer_over_real_runs() -> None:
    """The two richest recorded runs must reduce without loss or crashes."""
    for run_dir, min_agents, min_flows in (
        ("20260815-195935-juice-shop-ea92", 4, 6000),
        ("20260815-193336-dvwa-6251", 2, 20000),
    ):
        state = RunState()
        state.apply_all(_events(run_dir))
        assert state.events_seen == len(_events(run_dir))
        assert state.target, f"{run_dir}: target not captured"
        assert len(state.agents) >= min_agents
        assert state.flow_count >= min_flows
        assert state.findings, f"{run_dir}: findings not captured"
        assert state.stop_reason
        # every filed report_finding became a FindingView with sane fields
        for f in state.findings:
            assert f.severity in {"critical", "high", "medium", "low", "info"}
            assert f.by in {a.name for a in state.agents.values()}


def test_reducer_agent_lifecycle() -> None:
    state = RunState()
    state.apply_all([
        {"ts": "t0", "type": "scan_start", "target": "http://x", "model": "m",
         "mode": "graph", "budget_turns": 100, "proxy": True, "authenticated": True},
        {"ts": "t1", "type": "agent_start", "objective": "orchestrate",
         "agent_ctx": {"id": "a1", "name": "root", "role": "root"}},
        {"ts": "t2", "type": "agent_created", "agent_id": "a2", "agent": "sqli",
         "parent_id": "a1", "objective": "find sqli"},
        {"ts": "t3", "type": "agent_status", "agent_id": "a1", "agent": "root",
         "from": "running", "to": "waiting", "reason": "waiting for ['a2']"},
        {"ts": "t4", "type": "tool_call", "turn": 3, "name": "report_finding",
         "args": {"title": "SQLi", "severity": "critical", "url": "http://x/search"},
         "agent_ctx": {"id": "a2", "name": "sqli", "role": "specialist", "parent_id": "a1"}},
        {"ts": "t5", "type": "agent_end", "stop_reason": "agent_finish", "turns_used": 12,
         "total_tokens": 50000, "findings": 1,
         "agent_ctx": {"id": "a2", "name": "sqli", "role": "specialist"}},
        {"ts": "t6", "type": "scan_end", "stop_reason": "finish_tool",
         "turns_used": 40, "total_tokens": 90000, "findings": 1},
    ])
    assert state.agents["a1"].status == "waiting"
    root = state.agents["a1"]
    assert root.role == "root" and root.parent_id is None
    child = state.agents["a2"]
    assert child.parent_id == "a1"
    assert child.status == "completed"  # agent_end with agent_finish
    assert child.turns == 12 and child.findings == 1
    assert state.findings[0].title == "SQLi" and state.findings[0].by == "sqli"
    assert state.findings_total == 1
    assert state.live_agents() == [root]
    assert state.severity_counts() == {"critical": 1}


def test_reducer_phase3_events() -> None:
    state = RunState()
    state.apply_all([
        {"ts": "t1", "type": "proxy_started", "sidecar": "p1", "scope_hosts": ["x"]},
        {"ts": "t2", "type": "auth_established", "ok": True, "method": "api",
         "cookie_names": ["token"]},
        {"ts": "t3", "type": "proxy_flow", "i": 1, "method": "GET", "host": "x",
         "path": "/", "status": 200},
        {"ts": "t4", "type": "proxy_flow", "i": 2, "method": "GET", "host": "x",
         "path": "/a", "status": 404},
        {"ts": "t5", "type": "scope_blocked", "layer": "proxy", "host": "evil",
         "method": "CONNECT"},
        {"ts": "t6", "type": "screenshot", "artifact": "artifacts/a/1.png", "bytes": 10,
         "agent_ctx": {"id": "a1", "name": "xss", "role": "specialist"}},
        {"ts": "t7", "type": "agent_message", "from": "xss", "to": "root",
         "preview": "done"},
        {"ts": "t8", "type": "message_delivered", "from": "xss", "preview": "done",
         "agent_ctx": {"id": "a2", "name": "root", "role": "root"}},
        {"ts": "t9", "type": "totally_new_event", "whatever": 1},
    ])
    assert state.flow_count == 2 and state.flow_hosts == {"x": 2}
    assert state.blocked_count == 1 and state.blocked[0]["layer"] == "proxy"
    assert len(state.screenshots) == 1 and state.screenshots[0]["bytes"] == 10
    assert state.auth and state.auth["ok"]
    # unknown event types must not be dropped silently
    assert any("totally_new_event" in i.text for i in state.stream)
    # messages tracked separately from the stream
    assert len(state.messages) == 1 and "done" in state.messages[0].text


def test_format_tool_call_covers_all_engine_tools() -> None:
    assert "curl" in format_tool_call("exec_command", {"command": "curl http://x"})
    assert format_tool_call("think", {"thoughts": "hmm"}) .startswith("think")
    assert "recon" in format_tool_call("read_skill", {"name": "recon"})
    assert "SQLi" in format_tool_call("report_finding",
                                      {"title": "SQLi", "severity": "critical"})
    assert "browser.navigate" in format_tool_call("browser_navigate",
                                                  {"url": "http://x"})
    assert "browser.screenshot" in format_tool_call("browser_screenshot", {"label": "s"})
    assert "wait" in format_tool_call("wait_for_agents", {})
    assert format_tool_call("finish_scan", {}) == "finish_scan"
    assert format_tool_call("list_requests", {"id": 3}) .startswith("list_requests")


def test_replay_speed_sane() -> None:
    assert replay_speed_for(0) == 0
    small = replay_speed_for(100)
    big = replay_speed_for(25_000)
    assert 40 <= small <= big
    # 25k events replay in <= ~52s at the computed rate
    assert 25_000 / big <= 60
