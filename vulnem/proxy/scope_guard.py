"""mitmproxy addon: network-layer scope enforcement + flow logging.

Runs INSIDE the mitmproxy sidecar container (``vulnem/proxy/manager.py``
ships this file in and points mitmdump at it). This is the Phase 3 network
enforcement layer derived from ``vulnem/scope.py``:

- every request whose host is NOT in the operator-verified allowlist is
  BLOCKED (HTTP 403 / CONNECT denied) and appended to ``blocked.jsonl``;
- every completed exchange is appended to ``flows.jsonl`` as one JSON line
  (the proxy tools on the host read that file back via docker get_archive).

The allowlist arrives via the ``VULNEM_SCOPE_HOSTS`` environment variable
(comma-separated, set by the host when creating the sidecar) — never via the
agent, so no prompt can widen it.

Import safety: the pure helpers below (host_allowed, cookie-safe header
filtering, flow record building) have no mitmproxy imports, so the host test
suite can import this module directly.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time

MAX_BODY_BYTES = 8192  # per body captured into the flow log
SENSITIVE_REQ_HEADERS = {"authorization", "proxy-authorization", "cookie"}

try:  # only present inside the mitmproxy container
    from mitmproxy import http as m_http
except ImportError:  # host-side (tests) — hooks below never run there
    m_http = None

_FLOW_DIR = os.environ.get("VULNEM_FLOW_DIR", "/tmp/vulnem-flows")
_SCOPE_ENV = "VULNEM_SCOPE_HOSTS"
_write_lock = threading.Lock()
_flow_counter = 0


def allowed_hosts_from_env(env: dict[str, str] | None = None) -> set[str]:
    env = os.environ if env is None else env
    raw = env.get(_SCOPE_ENV, "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def host_allowed(host: str | None, allowed: set[str] | tuple[str, ...]) -> bool:
    """True when host (optionally carrying :port) is in the allowlist."""
    if not host:
        return False
    bare = host.split(":")[0].strip().lower().rstrip(".")
    return bare in {h.strip().lower().rstrip(".") for h in allowed}


def _b64(data: bytes | None, cap: int = MAX_BODY_BYTES) -> str:
    if not data:
        return ""
    return base64.b64encode(data[:cap]).decode("ascii")


def _headers_dict(headers, redact: bool = False) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        items = list(headers.items())
    except Exception:
        return out
    for key, value in items:
        name = key.decode("latin-1") if isinstance(key, bytes) else str(key)
        val = value.decode("latin-1", "replace") if isinstance(value, bytes) else str(value)
        if redact and name.lower() in SENSITIVE_REQ_HEADERS:
            out[name] = f"<redacted len={len(val)}>"
        else:
            out[name] = val[:500]
    return out


def build_flow_record(*, idx: int, client: str, method: str, host: str, port: int,
                      path: str, req_headers: dict, req_body_b64: str,
                      status_code: int | None, resp_headers: dict | None,
                      resp_body_b64: str, duration_ms: int = 0,
                      scheme: str = "http") -> dict:
    """Pure record builder (unit-testable without mitmproxy)."""
    return {
        "i": idx,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "client": client,
        "method": method,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path[:1000],
        "status": status_code,
        "req_headers": req_headers,
        "req_body": req_body_b64,
        "resp_headers": resp_headers or {},
        "resp_body": resp_body_b64,
        "duration_ms": duration_ms,
    }


def build_blocked_record(*, client: str, method: str, host: str,
                         reason: str = "out of scope") -> dict:
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "client": client,
        "method": method,
        "host": host,
        "reason": reason,
        "detail": "blocked by vulnem scope allowlist (VULNEM_SCOPE_HOSTS)",
    }


class ScopeGuard:
    """mitmproxy addon: block out-of-scope hosts, log every flow."""

    def __init__(self) -> None:
        self.allowed = allowed_hosts_from_env()
        self.started_at = time.time()

    def load(self, loader) -> None:
        self.allowed = allowed_hosts_from_env()

    # -- enforcement ---------------------------------------------------------

    def request(self, flow) -> None:
        host = flow.request.pretty_host
        if not host_allowed(host, self.allowed):
            self._log_blocked(flow, "out of scope")
            flow.response = m_http.Response.make(
                403,
                b"vulnem: request blocked - host is outside the authorized scope",
                {"Content-Type": "text/plain"},
            )
            flow.metadata["vulnem_blocked"] = True

    def http_connect(self, flow) -> None:
        host = flow.request.host
        if not host_allowed(host, self.allowed):
            self._log_blocked(flow, "out of scope (CONNECT)")
            # 402 is what mitmdump answers a denied CONNECT with; any non-2xx fails it.
            flow.response = m_http.Response.make(403, b"", {})

    # -- flow logging -----------------------------------------------------------

    def response(self, flow) -> None:
        global _flow_counter
        if flow.metadata.get("vulnem_blocked"):
            return  # blocked attempts live in blocked.jsonl only
        req, resp = flow.request, flow.response
        with _write_lock:
            _flow_counter += 1
            idx = _flow_counter
        record = build_flow_record(
            idx=idx,
            client=str(flow.client_conn.peername[0]) if flow.client_conn.peername else "",
            method=req.method,
            host=req.pretty_host,
            port=req.port or (443 if req.scheme == "https" else 80),
            path=req.path,
            req_headers=_headers_dict(req.headers, redact=True),
            req_body_b64=_b64(req.get_content() or b""),
            status_code=resp.status_code,
            resp_headers=_headers_dict(resp.headers),
            resp_body_b64=_b64(resp.get_content() or b""),
            duration_ms=int((resp.timestamp_end or 0) - (req.timestamp_start or 0)) * 1000
            if resp.timestamp_end and req.timestamp_start else 0,
            scheme=req.scheme or "http",
        )
        self._append("flows.jsonl", record)

    # -- helpers -----------------------------------------------------------------

    def _log_blocked(self, flow, reason: str) -> None:
        record = build_blocked_record(
            client=str(flow.client_conn.peername[0]) if flow.client_conn.peername else "",
            method=flow.request.method,
            host=flow.request.pretty_host or flow.request.host,
            reason=reason,
        )
        self._append("blocked.jsonl", record)

    def _append(self, name: str, record: dict) -> None:
        try:
            os.makedirs(_FLOW_DIR, exist_ok=True)
            with open(os.path.join(_FLOW_DIR, name), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass  # logging must never break the proxy


addons = [ScopeGuard()]
