"""Proxy + auth tests: scope addon logic, flow-log readers, proxy tools, creds,
ephemeral scan networks, mitm CA provisioning, proxy healthcheck wiring.

All offline: the mitmproxy addon's pure functions are imported directly, the
ProxyManager reads from a fake container serving tar archives, the proxy
tools run against that manager with a fake sandbox for replays, and the
Docker SDK client is faked wherever networks/containers would be touched.
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

import docker as docker_sdk

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
from vulnem.sandbox.docker import Sandbox
from vulnem.sandbox.network import ensure_scan_network, teardown_scan_network
from vulnem.scan import run_scan
from vulnem.scope import Scope


class _Res:
    def __init__(self, stdout="", exit_code=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
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


# -- ephemeral scan networks (docker SDK faked) ------------------------------------------


class FakeNetwork:
    def __init__(self, name):
        self.name = name
        self.removed = False
        self.connected: list[str] = []

    def remove(self):
        self.removed = True

    def connect(self, container):
        self.connected.append(container)


class FakeNetworksAPI:
    def __init__(self):
        self.created: list[dict] = []
        self.by_name: dict[str, FakeNetwork] = {}

    def create(self, name, driver=None, internal=None):
        self.created.append({"name": name, "driver": driver, "internal": internal})
        net = FakeNetwork(name)
        self.by_name[name] = net
        return net

    def get(self, name):
        return self.by_name[name]


class FakeSidecarContainer:
    """Everything ProxyManager.start() touches on the sidecar container."""

    def __init__(self):
        self.started = False
        self.removed = False

    def put_archive(self, path, data):
        return True

    def start(self):
        self.started = True

    def exec_run(self, cmd, **kwargs):  # _wait_listening probe succeeds
        return types.SimpleNamespace(exit_code=0, output=(b"", b""))

    def logs(self, tail=20):
        return b""

    def remove(self, **kwargs):
        self.removed = True


class FakeContainersAPI:
    def __init__(self, sidecar: FakeSidecarContainer):
        self.sidecar = sidecar
        self.created: list[dict] = []

    def create(self, image, **kwargs):
        self.created.append(kwargs)
        return self.sidecar


class FakeDockerClient:
    def __init__(self, sidecar=None):
        self.networks = FakeNetworksAPI()
        self.images = types.SimpleNamespace(
            get=lambda image: None, pull=lambda image: None
        )
        self.sidecar = sidecar or FakeSidecarContainer()
        self.containers = FakeContainersAPI(self.sidecar)


def test_ensure_scan_network_creates_ephemeral_when_unconfigured(monkeypatch):
    client = FakeDockerClient()
    monkeypatch.setattr(docker_sdk, "from_env", lambda: client)
    name = ensure_scan_network(None)
    assert name and name.startswith("vulnem-net-")
    assert len(name.rsplit("-", 1)[1]) == 8  # vulnem-net-<8hex>
    (created,) = client.networks.created
    assert created["name"] == name and created["driver"] == "bridge"
    # CRITICAL: not internal — the sandbox must reach live targets on the internet
    assert not created["internal"]


def test_configured_network_passes_through_unchanged(monkeypatch):
    client = FakeDockerClient()
    monkeypatch.setattr(docker_sdk, "from_env", lambda: client)
    assert ensure_scan_network("vulnem-lab_labnet") == "vulnem-lab_labnet"
    assert client.networks.created == []  # nothing ephemeral for lab scans


def test_teardown_scan_network_removes_and_swallows_errors(monkeypatch, caplog):
    client = FakeDockerClient()
    monkeypatch.setattr(docker_sdk, "from_env", lambda: client)
    net = client.networks.create("vulnem-net-deadbeef", driver="bridge")
    teardown_scan_network("vulnem-net-deadbeef")
    assert net.removed
    teardown_scan_network(None)  # no-op
    teardown_scan_network("vulnem-net-missing")  # unknown network: never raises


def test_manager_start_creates_ephemeral_network_and_teardown_removes(monkeypatch):
    client = FakeDockerClient()
    monkeypatch.setattr(docker_sdk, "from_env", lambda: client)
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    pm.start()
    net = pm.network
    assert net and net.startswith("vulnem-net-")
    # the sidecar was attached to the ephemeral network, not the default bridge
    (kwargs,) = client.containers.created
    assert kwargs["network"] == net
    assert client.sidecar.started
    pm.stop()
    assert client.sidecar.removed
    assert client.networks.by_name[net].removed  # network outlived the container


def test_manager_start_keeps_configured_network_and_never_removes_it(monkeypatch):
    client = FakeDockerClient()
    monkeypatch.setattr(docker_sdk, "from_env", lambda: client)
    lab = client.networks.create("vulnem-lab_labnet", driver="bridge", internal=True)
    pm = ProxyManager(scope=Scope.from_target("http://juice-shop:3000"),
                      network="vulnem-lab_labnet")
    pm.start()
    assert pm.network == "vulnem-lab_labnet"
    assert len(client.networks.created) == 1  # nothing ephemeral created
    pm.stop()
    assert not lab.removed  # the lab network belongs to the lab, not to us


# -- mitm CA provisioning --------------------------------------------------------------


class PathAwareContainer:
    """FakeContainer variant keyed by full container path (CA locations)."""

    def __init__(self, files: dict[str, str]):
        self.files = files

    def get_archive(self, path: str):
        if path not in self.files:
            raise FileNotFoundError(path)
        return iter([_tar_bytes(path.rsplit("/", 1)[-1], self.files[path])]), None


def test_get_ca_cert_prefers_mitmproxy_user_home():
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    pm._container = PathAwareContainer(
        {"/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem": "FAKE-CA"})
    assert pm.get_ca_cert() == b"FAKE-CA"


def test_get_ca_cert_falls_back_to_root_home():
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    pm._container = PathAwareContainer(
        {"/root/.mitmproxy/mitmproxy-ca-cert.pem": "ROOT-CA"})
    assert pm.get_ca_cert() == b"ROOT-CA"


def test_get_ca_cert_returns_none_on_missing_or_no_container():
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    pm._container = PathAwareContainer({})
    assert pm.get_ca_cert() is None
    pm2 = ProxyManager(scope=Scope.from_target("https://example.com"))
    assert pm2.get_ca_cert() is None  # never raises, even stopped


class FakeExecContainer:
    """Records exec_run calls and serves put_archive'd files back."""

    def __init__(self):
        self.calls: list[dict] = []
        self.files: dict[str, bytes] = {}
        self.next_exit_code = 0

    def put_archive(self, path, data):
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            member = tar.getmembers()[0]
            fh = tar.extractfile(member)
            self.files[f"{path}/{member.name}"] = fh.read() if fh else b""
        return True

    def exec_run(self, cmd, user=None, environment=None, demux=False):
        self.calls.append({"cmd": cmd, "user": user, "env": environment})
        code, self.next_exit_code = self.next_exit_code, 0
        return types.SimpleNamespace(exit_code=code, output=(b"", b""))


def _fake_sandbox() -> Sandbox:
    sb = Sandbox(image="img", user="pentester",
                 proxy_url="http://vulnem-proxy-x:8080")
    sb._container = FakeExecContainer()
    return sb


def test_install_proxy_ca_stages_cert_and_runs_one_root_exec():
    sb = _fake_sandbox()
    assert sb.install_proxy_ca(b"FAKE-CA") is True
    c = sb._container
    # the cert landed at /home/<user>/.vulnem/mitm-ca.pem via put_file
    assert c.files["/home/pentester/.vulnem/mitm-ca.pem"] == b"FAKE-CA"
    users = [call["user"] for call in c.calls]
    assert users[0] == "pentester"  # mkdir as the sandbox user
    root_calls = [call for call in c.calls if call["user"] == "0"]
    assert len(root_calls) == 1  # exactly ONE privileged exec
    script = root_calls[0]["cmd"][2]
    assert "update-ca-certificates" in script
    assert "/usr/local/share/ca-certificates/vulnem-mitm.crt" in script
    # merged bundle = system CA file + mitm CA, under the sandbox user's home
    assert "cat /etc/ssl/certs/ca-certificates.crt" in script
    assert "/home/pentester/.vulnem/ca-bundle.crt" in script


def test_exec_env_carries_proxy_and_ca_bundle_after_install():
    sb = _fake_sandbox()
    sb.exec("true")
    assert "SSL_CERT_FILE" not in sb._container.calls[-1]["env"]  # not yet installed
    assert sb.install_proxy_ca(b"FAKE-CA") is True
    sb.exec("curl -s https://example.com")
    env = sb._container.calls[-1]["env"]
    assert env["https_proxy"] == "http://vulnem-proxy-x:8080"
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
                "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"):
        assert env[var] == "/home/pentester/.vulnem/ca-bundle.crt"


def test_install_proxy_ca_failure_returns_false_without_side_effects():
    sb = _fake_sandbox()
    sb._container.next_exit_code = 1  # root exec fails
    assert sb.install_proxy_ca(b"FAKE-CA") is False
    sb.exec("true")  # must NOT claim a bundle exists
    assert "SSL_CERT_FILE" not in sb._container.calls[-1]["env"]


# -- proxy healthcheck ------------------------------------------------------------------


class _CurlSandbox(FakeSandbox):
    def __init__(self, status: str, exit_code: int = 0, stderr: str = ""):
        super().__init__()
        self._status = status
        self._exit_code = exit_code
        self._stderr = stderr

    def exec(self, command: str, *, timeout: int = 120):
        self.commands.append(command)
        return _Res(stdout=self._status, exit_code=self._exit_code)


def test_healthcheck_probes_target_through_proxy_env():
    pm = ProxyManager(scope=Scope.from_target("http://juice-shop:3000"))
    sb = _CurlSandbox("204")
    ok, detail = pm.healthcheck(sb)
    assert ok and detail == "204"
    cmd = sb.commands[-1]
    assert cmd.startswith("curl -sS -o /dev/null -w '%{http_code}'")
    assert "-x \"$https_proxy\"" in cmd and "http://juice-shop:3000/" in cmd


def test_healthcheck_https_target_uses_https_url():
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    sb = _CurlSandbox("200")
    ok, _ = pm.healthcheck(sb)
    assert ok and "https://example.com/" in sb.commands[-1]


def test_healthcheck_detects_broken_proxy():
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    ok, reason = pm.healthcheck(_CurlSandbox("000"))
    assert not ok and "000" in reason
    ok, reason = pm.healthcheck(_CurlSandbox("", exit_code=7))
    assert not ok and "curl via proxy failed" in reason
    ok, reason = pm.healthcheck(_CurlSandbox(""))
    assert not ok and "no status" in reason


def test_healthcheck_treats_unparseable_fake_output_as_success():
    # Fake sandboxes replay full HTTP responses, not bare status codes;
    # "something answered through the proxy" must count as healthy.
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    ok, detail = pm.healthcheck(FakeSandbox())
    assert ok and detail == "answered"


def test_healthcheck_survives_sandboxes_without_timeout_kwarg():
    class Minimal:
        def exec(self, command):  # no timeout kwarg at all
            return _Res(stdout="200")

    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    ok, _ = pm.healthcheck(Minimal())
    assert ok


# -- run_scan wiring: proxy_ready / proxy_down honesty -----------------------------------


class _Resp:
    def __init__(self, idx, text, name, args):
        if name is None:
            message = types.SimpleNamespace(content=text, tool_calls=None)
        else:
            tc = types.SimpleNamespace(
                id=f"call_{idx}",
                function=types.SimpleNamespace(name=name, arguments=args),
            )
            message = types.SimpleNamespace(content=text, tool_calls=[tc])
        usage = types.SimpleNamespace(prompt_tokens=10, completion_tokens=5)
        self.choices = [types.SimpleNamespace(message=message)]
        self.usage = usage


class SoloLLM:
    """Smallest scripted completion_fn: think once, then finish."""

    def __init__(self):
        self.queue = [("", "think", {"thoughts": "plan"}),
                      ("Done.", "finish_scan", {"summary": "scan complete"})]
        self._i = 0

    def __call__(self, messages, tools):
        text, name, args = self.queue.pop(0)
        self._i += 1
        return _Resp(self._i, text, name, json.dumps(args))


class ScanSandbox(FakeSandbox):
    """FakeSandbox + the surface run_scan's proxy wiring touches."""

    network = None
    container_name = "vulnem-sandbox-fake01"
    proxy_url = "http://vulnem-proxy-fake:8080"

    def __init__(self):
        super().__init__()
        self.ca: bytes | None = None

    def install_proxy_ca(self, cert_bytes: bytes) -> bool:
        self.ca = cert_bytes
        return True


class CurlFailSandbox(ScanSandbox):
    def exec(self, command: str, *, timeout: int = 120):
        self.commands.append(command)
        return _Res(stdout="", exit_code=7,
                    stderr="curl: (7) Could not resolve proxy vulnem-proxy-x")


def _write_run_config(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(json.dumps({
        "target": "https://example.com", "model": "fake/model",
        "network": None, "proxy": True, "started_at": "t0",
    }), encoding="utf-8")


def _transcript_events(tmp_path: Path) -> list[dict]:
    return [json.loads(line)
            for line in (tmp_path / "transcript.jsonl").read_text(
                encoding="utf-8").splitlines()]


async def _run_with_proxy(tmp_path, sandbox, proxy) -> None:
    await run_scan(scope=Scope.from_target("https://example.com"),
                   settings=Settings(model="fake/model"), sandbox=sandbox,
                   run_dir=tmp_path, solo=True, completion_fn=SoloLLM(),
                   proxy=proxy)


@pytest.mark.asyncio
async def test_proxy_ready_event_and_honest_config_on_success(tmp_path):
    _write_run_config(tmp_path)
    sb = ScanSandbox()
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    pm._container = FakeContainer({"mitmproxy-ca-cert.pem": "FAKE-CA",
                                   "flows.jsonl": "", "blocked.jsonl": ""})

    await _run_with_proxy(tmp_path, sb, pm)

    assert sb.ca == b"FAKE-CA"  # CA fetched from the sidecar and installed
    events = _transcript_events(tmp_path)
    kinds = [e["type"] for e in events]
    assert "proxy_started" in kinds and "proxy_ready" in kinds
    ready = next(e for e in events if e["type"] == "proxy_ready")
    assert ready["ca_installed"] is True and ready["network"] == "default"
    config = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert config["proxy_effective"] is True
    end = next(e for e in events if e["type"] == "scan_end")
    assert end["proxy_effective"] is True


@pytest.mark.asyncio
async def test_proxy_down_event_marks_config_and_scan_continues(tmp_path):
    _write_run_config(tmp_path)
    sb = CurlFailSandbox()
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    pm._container = FakeContainer({"mitmproxy-ca-cert.pem": "FAKE-CA",
                                   "flows.jsonl": "", "blocked.jsonl": ""})

    await _run_with_proxy(tmp_path, sb, pm)

    events = _transcript_events(tmp_path)
    kinds = [e["type"] for e in events]
    assert "proxy_ready" not in kinds and "proxy_down" in kinds
    down = next(e for e in events if e["type"] == "proxy_down")
    assert "proxy" in down["reason"]
    # the scan CONTINUED to a clean finish despite the broken network layer
    assert "scan_end" in kinds
    end = next(e for e in events if e["type"] == "scan_end")
    assert end["proxy_effective"] is False
    # the run record no longer silently claims the network layer is active
    config = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert config["proxy"] is True and config["proxy_effective"] is False


@pytest.mark.asyncio
async def test_scan_survives_sandbox_without_ca_installer(tmp_path):
    _write_run_config(tmp_path)
    sb = FakeSandbox()  # no install_proxy_ca / container_name attributes at all
    pm = ProxyManager(scope=Scope.from_target("https://example.com"))
    pm._container = FakeContainer({"mitmproxy-ca-cert.pem": "FAKE-CA",
                                   "flows.jsonl": "", "blocked.jsonl": ""})

    await _run_with_proxy(tmp_path, sb, pm)

    events = _transcript_events(tmp_path)
    ready = next(e for e in events if e["type"] == "proxy_ready")
    assert ready["ca_installed"] is False  # graceful degradation, not a crash
    config = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert config["proxy_effective"] is True
