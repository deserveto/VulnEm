"""Proxy + auth tests: scope addon logic, flow-log readers, proxy tools, creds.

All offline: the mitmproxy addon's pure functions are imported directly, the
ProxyManager reads from a fake container serving tar archives, and the proxy
tools run against that manager with a fake sandbox for replays.
"""

from __future__ import annotations

import base64
import io
import json
import sys
import tarfile
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnem.agent.tools import ToolContext, dispatch_tool
from vulnem.auth import (
    AuthResult,
    CredsConfig,
    CredsError,
    _parse_set_cookies,
    cookies_to_netscape,
    stage_session,
)
from vulnem.config import Settings
from vulnem.proxy import scope_guard
from vulnem.proxy.manager import ProxyManager
from vulnem.scope import Scope


class _Res:
    def __init__(self, stdout="", exit_code=0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_code = exit_code
        self.duration = 0.01


class FakeSandbox:
    def __init__(self):
        self.files: dict[str, bytes] = {}
        self.commands: list[str] = []

    def exec(self, command: str, *, timeout: int = 120):
        self.commands.append(command)
        return _Res(stdout="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nreplayed-body")

    def put_file(self, data: bytes, container_path: str) -> None:
        self.files[container_path] = data

    def get_file(self, container_path: str) -> bytes:
        return b""


def _tar_bytes(name: str, content: str) -> bytes:
    data = content.encode("utf-8")
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeContainer:
    def __init__(self, files: dict[str, str]):
        self.files = files

    def get_archive(self, path: str):
        name = path.rsplit("/", 1)[-1]
        if name not in self.files:
            raise FileNotFoundError(path)
        return iter([_tar_bytes(name, self.files[name])]), None


class FakeProxy:
    """ProxyManager stand-in serving canned flow/blocked logs."""

    def __init__(self, flows, blocked=()):
        self._flows = flows
        self._blocked = list(blocked)
        self.name = "vulnem-proxy-test"
        self.sandbox_proxy_url = "http://vulnem-proxy-test:8080"

    def read_flows(self):
        return self._flows

    def read_blocked(self):
        return self._blocked


def _flow(i=1, method="GET", host="juice-shop", port=3000, path="/rest/products/search?q=x",
          status=200, body="hello", scheme="http"):
    return scope_guard.build_flow_record(
        idx=i, client="10.0.0.2", method=method, host=host, port=port, path=path,
        req_headers={"host": f"{host}:{port}", "authorization": "<redacted len=31>"},
        req_body_b64=base64.b64encode(body.encode()).decode(),
        status_code=status, resp_headers={"content-type": "application/json"},
        resp_body_b64=base64.b64encode(b'{"r":1}').decode(),
        duration_ms=12, scheme=scheme,
    )


def make_ctx(sandbox, proxy, tmp_path):
    ctx = ToolContext(
        settings=Settings(model="fake/model"),
        sandbox=sandbox,
        scope_host="juice-shop",
        agent_name="sqli-probe",
        allowed_hosts=("juice-shop", "juice-shop.localhost"),
        proxy=proxy,
        run_dir=tmp_path,
    )
    events: list[dict] = []
    ctx.emit_event = events.append
    return ctx, events


# -- addon pure logic ---------------------------------------------------------------


def test_host_allowed_matches_ports_case_and_dots():
    allowed = {"Juice-Shop", "juice-shop.localhost"}
    assert scope_guard.host_allowed("juice-shop", allowed)
    assert scope_guard.host_allowed("juice-shop:3000", allowed)
    assert scope_guard.host_allowed("JUICE-SHOP.", allowed)
    assert not scope_guard.host_allowed("evil.com", allowed)
    assert not scope_guard.host_allowed("juice-shop.evil.com", allowed)
    assert not scope_guard.host_allowed("", allowed)
    assert not scope_guard.host_allowed(None, allowed)


def test_allowed_hosts_from_env():
    env = {"VULNEM_SCOPE_HOSTS": "a.com, B.com ,,"}
    assert scope_guard.allowed_hosts_from_env(env) == {"a.com", "b.com"}


def test_flow_record_shape():
    rec = _flow(i=7, method="POST", body='{"q":"x"}')
    assert rec["i"] == 7 and rec["method"] == "POST" and rec["scheme"] == "http"
    assert base64.b64decode(rec["req_body"]) == b'{"q":"x"}'
    assert rec["status"] == 200 and rec["host"] == "juice-shop"


def test_build_blocked_record():
    rec = scope_guard.build_blocked_record(client="10.0.0.2", method="GET", host="evil.com")
    assert rec["host"] == "evil.com" and "scope" in rec["reason"]


# -- ProxyManager log readers ----------------------------------------------------------


def test_manager_reads_flow_log_from_tar(tmp_path):
    flows = [_flow(i=1), _flow(i=2, method="POST", path="/api/Feedback")]
    content = "".join(json.dumps(f) + "\n" for f in flows)
    pm = ProxyManager(scope=Scope.from_target("http://juice-shop:3000"))
    pm._container = FakeContainer({"flows.jsonl": content, "blocked.jsonl": ""})
    assert [f["i"] for f in pm.read_flows()] == [1, 2]
    assert pm.read_blocked() == []


def test_manager_missing_log_is_empty(tmp_path):
    pm = ProxyManager(scope=Scope.from_target("http://juice-shop:3000"))
    pm._container = FakeContainer({})
    assert pm.read_flows() == []
    assert pm.read_blocked() == []


def test_manager_emits_new_flow_and_blocked_events(tmp_path):
    flows = [_flow(i=1)]
    blocked = [scope_guard.build_blocked_record(client="c", method="GET", host="evil.com")]
    pm = ProxyManager(scope=Scope.from_target("http://juice-shop:3000"))
    pm._container = FakeContainer({
        "flows.jsonl": json.dumps(flows[0]) + "\n",
        "blocked.jsonl": json.dumps(blocked[0]) + "\n",
    })

    emitted = []
    coordinator = types.SimpleNamespace(emit=emitted.append)
    pm.bind(coordinator, tmp_path)
    pm._emit_new(pm.read_flows(), pm.read_blocked())
    kinds = [e["type"] for e in emitted]
    assert kinds == ["proxy_flow", "scope_blocked"]
    assert emitted[0]["path"].startswith("/rest/products")
    assert (tmp_path / "proxy-blocked.jsonl").is_file()

    # second call with no new data emits nothing
    emitted.clear()
    pm._emit_new(pm.read_flows(), pm.read_blocked())
    assert emitted == []


# -- proxy tools ------------------------------------------------------------------------


def test_list_requests_filters_and_pages(tmp_path):
    flows = [_flow(i=i, path=f"/p{i}") for i in range(1, 6)] + \
            [_flow(i=6, method="POST", path="/api/Feedback")]
    ctx, _events = make_ctx(FakeSandbox(), FakeProxy(flows), tmp_path)
    result = json.loads(dispatch_tool("list_requests", {"q": "feedback"}, ctx))
    assert result["ok"] and result["total_captured"] == 6
    assert [r["id"] for r in result["requests"]] == [6]
    result = json.loads(dispatch_tool("list_requests", {"limit": 2}, ctx))
    assert result["returned"] == 2


def test_view_request_details_and_redaction(tmp_path):
    flows = [_flow(i=3, method="POST", body='{"comment":"<img src=x>"}')]
    ctx, _events = make_ctx(FakeSandbox(), FakeProxy(flows), tmp_path)
    result = json.loads(dispatch_tool("view_request", {"id": 3}, ctx))
    assert result["ok"]
    assert "<img src=x>" in result["request_body"]
    assert result["url"] == "http://juice-shop:3000/rest/products/search?q=x"
    assert result["request_headers"]["authorization"].startswith("<redacted")
    assert json.loads(dispatch_tool("view_request", {"id": 99}, ctx))["ok"] is False


def test_repeat_request_replays_in_scope(tmp_path):
    flows = [_flow(i=2, method="POST", body='{"comment":"hi"}')]
    sb = FakeSandbox()
    ctx, _events = make_ctx(sb, FakeProxy(flows), tmp_path)
    result = json.loads(dispatch_tool(
        "repeat_request", {"id": 2, "modifications": {"body": '{"comment":"<img src=x onerror=1>"}'}}, ctx))
    assert result["ok"]
    assert "replayed-body" in result["response"]
    cmd = sb.commands[-1]
    assert cmd.startswith("curl -s -i") and "-X POST" in cmd
    assert "http://juice-shop:3000/rest/products/search" in cmd
    assert sb.files["/tmp/.vulnem-repeat-body.json"] == b'{"comment":"<img src=x onerror=1>"}'


def test_repeat_request_blocks_out_of_scope_modification(tmp_path):
    flows = [_flow(i=1)]
    sb = FakeSandbox()
    ctx, events = make_ctx(sb, FakeProxy(flows), tmp_path)
    result = json.loads(dispatch_tool(
        "repeat_request", {"id": 1, "modifications": {"url": "http://evil.com/steal"}}, ctx))
    assert not result["ok"] and "OUT OF SCOPE" in result["error"]
    assert sb.commands == []  # never reached the sandbox
    assert any(e["type"] == "scope_blocked" for e in events)


def test_repeat_request_uses_cookie_jar_when_authenticated(tmp_path):
    flows = [_flow(i=1)]
    sb = FakeSandbox()
    ctx, _events = make_ctx(sb, FakeProxy(flows), tmp_path)
    ctx.auth_cookies = [{"name": "token", "value": "v", "domain": "juice-shop"}]
    json.loads(dispatch_tool("repeat_request", {"id": 1}, ctx))
    assert "-b /home/pentester/cookies.txt" in sb.commands[-1]


def test_view_sitemap_renders_tree(tmp_path):
    flows = [_flow(i=1, path="/a?x=1"), _flow(i=2, method="POST", path="/a"),
             _flow(i=3, host="juice-shop.localhost", path="/b")]
    ctx, _events = make_ctx(FakeSandbox(), FakeProxy(flows), tmp_path)
    out = json.loads(dispatch_tool("view_sitemap", {}, ctx))
    assert out["ok"]
    out if isinstance(out, str) else json.dumps(out)
    result = dispatch_tool("view_sitemap", {}, ctx)
    assert "[GET,POST] /a" in result
    assert "juice-shop.localhost" in result


def test_proxy_tools_without_sidecar_error_cleanly(tmp_path):
    ctx, _ = make_ctx(FakeSandbox(), None, tmp_path)
    result = json.loads(dispatch_tool("list_requests", {}, ctx))
    assert not result["ok"] and "proxy" in result["error"]


# -- creds / auth -------------------------------------------------------------------------


def test_creds_load_and_validation(tmp_path):
    path = tmp_path / "creds.json"
    path.write_text(json.dumps({
        "login_url": "http://t/login", "method": "api",
        "api": {"method": "POST", "url": "http://t/api/login",
                "json": {"u": "admin", "p": "x"}}}), encoding="utf-8")
    cfg = CredsConfig.load(path)
    assert cfg.method == "api" and cfg.api["url"] == "http://t/api/login"
    with pytest.raises(CredsError):
        CredsConfig.load(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text('{"method": "banana"}', encoding="utf-8")
    with pytest.raises(CredsError, match="browser\\|api\\|cookies"):
        CredsConfig.load(bad)


def test_parse_set_cookies_and_netscape_jar():
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: token=abc123; Path=/; HttpOnly\r\n"
        "Set-Cookie: stats=xyz; Domain=.t.com; Path=/track; Secure\r\n"
        "\r\nbody"
    )
    cookies = _parse_set_cookies(raw, "http://t.com/login")
    assert {c["name"]: c["value"] for c in cookies} == {"token": "abc123", "stats": "xyz"}
    jar = cookies_to_netscape(cookies)
    lines = [ln for ln in jar.splitlines() if ln and not ln.startswith("#HttpOnly")]
    assert any("\ttoken\tabc123" in ln for ln in lines)


def test_stage_session_writes_jar(tmp_path):
    sb = FakeSandbox()
    auth = AuthResult(ok=True, method="api", cookies=[
        {"name": "token", "value": "v", "domain": "t.com", "path": "/"}])
    stage_session(sb, auth)
    jar = sb.files["/home/pentester/cookies.txt"].decode()
    assert "token" in jar and "v" in jar


def test_auth_result_describe_hides_values():
    auth = AuthResult(ok=True, method="api", detail="login ok",
                      cookies=[{"name": "token", "value": "SECRET"}],
                      cookie_names=["token"])
    described = json.dumps(auth.describe())
    assert "SECRET" not in described and "token" in described


def test_api_login_via_fake_sandbox(tmp_path):
    creds = CredsConfig(login_url="http://t/login", method="api",
                        api={"method": "POST", "url": "http://t/api/login",
                             "json": {"u": "admin", "p": "x"}})
    from vulnem.auth import AuthSession

    class LoginSandbox(FakeSandbox):
        def exec(self, command, *, timeout=120):
            self.commands.append(command)
            return _Res(stdout="HTTP/1.1 200 OK\r\nSet-Cookie: session=k1; Path=/\r\n\r\n{}")

    sb = LoginSandbox()
    auth = AuthSession(creds).establish(sandbox=sb)
    assert auth.ok and auth.cookie_names == ["session"]
    assert "curl" in sb.commands[0] and "api/login" in sb.commands[0]
    # the secret payload was staged as a file, not inlined in the command
    assert "admin" not in sb.commands[0]
    assert sb.files["/tmp/.vulnem-login.json"]
