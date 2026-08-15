"""Browser tool tests with a fake sandbox that emulates the in-container daemon.

No Docker, no Chromium: the fake sandbox answers the daemon's localhost HTTP
protocol with canned JSON, so we exercise the host-side plumbing — daemon
bring-up, per-agent session keying, cookie seeding, scope refusal, and
screenshot artifact persistence.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnem.agent.tools import ToolContext, dispatch_tool
from vulnem.config import Settings
from vulnem.tools import browser


class _Res:
    def __init__(self, stdout="", exit_code=0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_code = exit_code
        self.duration = 0.01


class FakeDaemonSandbox:
    """Emulates Sandbox.exec/put_file/get_file around a canned daemon."""

    def __init__(self, responses=None):
        self.files: dict[str, bytes] = {}
        self.ops: list[dict] = []
        self.exec_log: list[str] = []
        self.responses = responses or {}

    def exec(self, command: str, *, timeout: int = 120):
        self.exec_log.append(command)
        if '"op":"ping"' in command:
            return _Res(stdout=json.dumps({"ok": True, "chromium": True}))
        if "--data-binary @/tmp/.vulnem-browser-cmd.json" in command:
            op = json.loads(self.files["/tmp/.vulnem-browser-cmd.json"])
            self.ops.append(op)
            resp = self.responses.get(op.get("op"), {"ok": False, "error": f"op {op.get('op')} not scripted"})
            if callable(resp):
                resp = resp(op)
            return _Res(stdout=json.dumps(resp))
        return _Res(stdout="")

    def put_file(self, data: bytes, container_path: str) -> None:
        self.files[container_path] = data

    def get_file(self, container_path: str) -> bytes:
        return b"\x89PNG\r\n\x1a\nfake-png-bytes"


def make_ctx(sandbox, tmp_path, *, allowed=("juice-shop", "juice-shop.localhost"),
             agent="xss-probe", auth_cookies=None, proxy=None):
    ctx = ToolContext(
        settings=Settings(model="fake/model"),
        sandbox=sandbox,
        scope_host=allowed[0],
        agent_name=agent,
        allowed_hosts=tuple(allowed),
        proxy=proxy,
        run_dir=tmp_path,
    )
    events: list[dict] = []
    ctx.emit_event = events.append
    if auth_cookies:
        ctx.auth_cookies = auth_cookies
    return ctx, events


@pytest.fixture(autouse=True)
def _fresh_daemon_state():
    browser.reset_daemon_state()
    yield
    browser.reset_daemon_state()


# -- scope ----------------------------------------------------------------------


def test_host_in_scope():
    allowed = ("juice-shop", "juice-shop.localhost")
    assert browser.host_in_scope("http://juice-shop:3000/#/x", allowed)
    assert browser.host_in_scope("http://JUICE-SHOP/", allowed)
    assert not browser.host_in_scope("http://evil.com/", allowed)
    assert not browser.host_in_scope("http://juice-shop.evil.com/", allowed)
    assert not browser.host_in_scope("not a url", allowed)
    assert not browser.host_in_scope("", allowed)


def test_navigate_refuses_out_of_scope(tmp_path):
    sb = FakeDaemonSandbox()
    ctx, events = make_ctx(sb, tmp_path)
    result = json.loads(dispatch_tool("browser_navigate", {"url": "http://evil.com/x"}, ctx))
    assert not result["ok"]
    assert "OUT OF SCOPE" in result["error"]
    # refused before any daemon op ran
    assert sb.ops == []
    blocked = [e for e in events if e["type"] == "scope_blocked"]
    assert blocked and blocked[0]["layer"] == "browser-tool"


def test_navigate_success_keyed_to_agent(tmp_path):
    sb = FakeDaemonSandbox(responses={"navigate": {"ok": True, "status": 200, "title": "Shop"}})
    ctx, _events = make_ctx(sb, tmp_path)
    result = json.loads(dispatch_tool("browser_navigate", {"url": "http://juice-shop:3000/"}, ctx))
    assert result["ok"] and result["status"] == 200
    nav = sb.ops[-1]
    assert nav["op"] == "navigate" and nav["agent"] == "xss-probe"
    assert nav["url"] == "http://juice-shop:3000/"


def test_parallel_agents_get_separate_daemon_sessions(tmp_path):
    sb = FakeDaemonSandbox(responses={"navigate": {"ok": True}})
    ctx_a, _ = make_ctx(sb, tmp_path, agent="agent-a")
    ctx_b, _ = make_ctx(sb, tmp_path, agent="agent-b")
    dispatch_tool("browser_navigate", {"url": "http://juice-shop:3000/"}, ctx_a)
    dispatch_tool("browser_navigate", {"url": "http://juice-shop:3000/search"}, ctx_b)
    agents = [op["agent"] for op in sb.ops if op["op"] == "navigate"]
    assert agents == ["agent-a", "agent-b"]


# -- auth seeding -----------------------------------------------------------------


def test_auth_cookies_seeded_once_per_agent(tmp_path):
    sb = FakeDaemonSandbox(responses={"navigate": {"ok": True},
                                      "set_cookies": {"ok": True, "n": 2}})
    cookies = [{"name": "token", "value": "sekrit", "domain": "juice-shop", "path": "/"}]
    ctx, _ = make_ctx(sb, tmp_path, auth_cookies=cookies)
    dispatch_tool("browser_navigate", {"url": "http://juice-shop:3000/"}, ctx)
    dispatch_tool("browser_read_page", {}, ctx)
    seeds = [op for op in sb.ops if op["op"] == "set_cookies"]
    assert len(seeds) == 1 and seeds[0]["cookies"] == cookies


# -- read_page + screenshot ----------------------------------------------------------


def test_read_page_truncates_text(tmp_path):
    sb = FakeDaemonSandbox(responses={"read_page": {"ok": True, "url": "http://juice-shop:3000/",
                                                    "title": "t", "text": "x" * 20_000,
                                                    "links": [], "inputs": [], "dialogs": []}})
    ctx, _events = make_ctx(sb, tmp_path)
    result = json.loads(dispatch_tool("browser_read_page", {}, ctx))
    assert result["ok"]
    assert len(result["text"]) < 7_000
    assert "truncated" in result["text"]


def test_screenshot_persists_artifact_and_emits_event(tmp_path):
    sb = FakeDaemonSandbox(responses={
        "screenshot": {"ok": True, "path": "/home/pentester/artifacts/xss-probe/123-evidence.png"}})
    ctx, events = make_ctx(sb, tmp_path)
    result = json.loads(dispatch_tool("browser_screenshot", {"name": "evidence"}, ctx))
    assert result["ok"]
    assert result["artifact"] == "artifacts/xss-probe/123-evidence.png"
    artifact = tmp_path / "artifacts" / "xss-probe" / "123-evidence.png"
    assert artifact.read_bytes() == b"\x89PNG\r\n\x1a\nfake-png-bytes"
    shots = [e for e in events if e["type"] == "screenshot"]
    assert shots and shots[0]["artifact"] == result["artifact"]
    assert shots[0]["bytes"] > 0


def test_fill_requires_value(tmp_path):
    ctx, _ = make_ctx(FakeDaemonSandbox(), tmp_path)
    result = json.loads(dispatch_tool("browser_fill", {"selector": "#q"}, ctx))
    assert not result["ok"]


def test_daemon_restart_when_unresponsive(tmp_path, monkeypatch):
    # Daemon "died": ping succeeds first call, then the sandbox stops answering.
    monkeypatch.setattr(browser, "DAEMON_START_RETRIES", 2)
    monkeypatch.setattr(browser, "DAEMON_START_DELAY", 0.01)

    class FlakySandbox(FakeDaemonSandbox):
        def __init__(self):
            super().__init__({"navigate": {"ok": True}})
            self.broken = False

        def exec(self, command, *, timeout=120):
            if self.broken:
                return _Res(stdout="", exit_code=7)
            return super().exec(command)

    sb = FlakySandbox()
    ctx, _ = make_ctx(sb, tmp_path)
    assert json.loads(dispatch_tool("browser_navigate", {"url": "http://juice-shop:3000/"}, ctx))["ok"]
    sb.broken = True
    result = json.loads(dispatch_tool("browser_navigate", {"url": "http://juice-shop:3000/"}, ctx))
    assert not result["ok"]  # surfaced cleanly, no exception
