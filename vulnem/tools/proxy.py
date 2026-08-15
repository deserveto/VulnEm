"""Proxy tools: inspect and replay the traffic the scan generated.

All data comes from the mitmproxy sidecar's flow log (every request the
sandbox made through the proxy, with bodies capped). ``repeat_request``
re-issues a captured request FROM THE SANDBOX through the same proxy, so
the replay is scope-checked by the network layer exactly like the original —
it can never bypass scope.
"""

from __future__ import annotations

import base64
import json
import shlex
from typing import Any

from vulnem.textutil import truncate

# Header names that must not be blindly replayed from the captured record.
_HOP_HEADERS = {"host", "content-length", "connection", "accept-encoding",
                "proxy-connection", "transfer-encoding", "cookie"}
BODY_FILE = "/tmp/.vulnem-repeat-body.json"


def _no_proxy(ctx) -> str:
    if getattr(ctx, "proxy", None) is None:
        return json.dumps({
            "ok": False,
            "error": "the proxy sidecar is not enabled for this scan "
                     "(start without --no-proxy to use proxy tools)",
        })
    return ""


def _flows(ctx) -> list[dict]:
    return ctx.proxy.read_flows()


def _b64_to_text(b64: str, cap: int = 2000) -> str:
    if not b64:
        return ""
    try:
        raw = base64.b64decode(b64)
    except (ValueError, TypeError):
        return "(undecodable body)"
    text = raw[:cap].decode("utf-8", "replace")
    if len(raw) > cap:
        text += f"\n... [{len(raw) - cap} more bytes]"
    return text


# -- handlers (sync, run in worker threads) --------------------------------------


def _tool_list_requests(ctx, args: dict[str, Any]) -> str:
    refused = _no_proxy(ctx)
    if refused:
        return refused
    flows = _flows(ctx)
    q = str(args.get("q") or "").lower()
    method = str(args.get("method") or "").upper()
    status = args.get("status")
    limit = max(1, min(int(args.get("limit") or 30), 200))
    rows = []
    for rec in flows:
        if q and q not in (rec.get("path") or "").lower() and q not in (rec.get("host") or "").lower():
            continue
        if method and method != (rec.get("method") or "").upper():
            continue
        if status is not None and int(status) != rec.get("status"):
            continue
        rows.append({
            "id": rec.get("i"),
            "method": rec.get("method"),
            "host": rec.get("host"),
            "path": (rec.get("path") or "")[:120],
            "status": rec.get("status"),
        })
    tail = rows[-limit:]  # most recent window
    return json.dumps({
        "ok": True,
        "total_captured": len(flows),
        "returned": len(tail),
        "note": "most recent matches shown; use view_request with an id for detail",
        "requests": tail,
    }, ensure_ascii=False)


def _tool_view_request(ctx, args: dict[str, Any]) -> str:
    refused = _no_proxy(ctx)
    if refused:
        return refused
    try:
        rid = int(args["id"])
    except (KeyError, TypeError, ValueError):
        return json.dumps({"ok": False, "error": "id (integer) is required"})
    rec = next((r for r in _flows(ctx) if r.get("i") == rid), None)
    if rec is None:
        return json.dumps({"ok": False, "error": f"no captured request with id {rid}"})
    detail = {
        "ok": True,
        "id": rid,
        "ts": rec.get("ts"),
        "method": rec.get("method"),
        "url": _record_url(rec),
        "status": rec.get("status"),
        "duration_ms": rec.get("duration_ms"),
        "request_headers": rec.get("req_headers"),
        "request_body": _b64_to_text(rec.get("req_body") or ""),
        "response_headers": rec.get("resp_headers"),
        "response_body": _b64_to_text(rec.get("resp_body") or ""),
        "note": "replay with repeat_request (re-issued from the sandbox through "
                "the proxy, using the authenticated session)",
    }
    return json.dumps(detail, ensure_ascii=False)


def _record_url(rec: dict) -> str:
    scheme = rec.get("scheme") or "http"
    port = rec.get("port") or 80
    if (scheme, port) in (("http", 80), ("https", 443)):
        return f"{scheme}://{rec.get('host')}{rec.get('path') or '/'}"
    return f"{scheme}://{rec.get('host')}:{port}{rec.get('path') or '/'}"


def _tool_repeat_request(ctx, args: dict[str, Any]) -> str:
    from vulnem.tools.browser import _scope_guard  # same host-level check as browser

    refused = _no_proxy(ctx)
    if refused:
        return refused
    try:
        rid = int(args["id"])
    except (KeyError, TypeError, ValueError):
        return json.dumps({"ok": False, "error": "id (integer) is required"})
    rec = next((r for r in _flows(ctx) if r.get("i") == rid), None)
    if rec is None:
        return json.dumps({"ok": False, "error": f"no captured request with id {rid}"})

    mods = args.get("modifications") or {}
    url = str(mods.get("url") or _record_url(rec))
    blocked = _scope_guard(ctx, url)
    if blocked:
        return blocked
    method = str(mods.get("method") or rec.get("method") or "GET").upper()

    parts = [f"curl -s -i --compressed -m 60 -X {shlex.quote(method)} {shlex.quote(url)}"]
    # Forward captured headers except hop-by-hop/redacted ones; the replay's
    # Cookie comes from the live authenticated session (cookies.txt), not the
    # redacted log.
    for name, value in (rec.get("req_headers") or {}).items():
        if name.lower() in _HOP_HEADERS or value.startswith("<redacted"):
            continue
        parts.append(f"-H {shlex.quote(f'{name}: {value}')}")
    if ctx.auth_cookies:
        parts.append("-b /home/pentester/cookies.txt")
    body = str(mods.get("body") if "body" in mods else _b64_to_text(rec.get("req_body") or "", cap=64_000))
    if body:
        try:
            ctx.sandbox.put_file(body.encode("utf-8"), BODY_FILE)
            parts.append(f"-H 'Content-Type: application/json' --data-binary @{BODY_FILE}")
        except Exception as exc:
            return json.dumps({"ok": False, "error": f"could not stage body: {exc}"})
    command = " ".join(parts)
    res = ctx.sandbox.exec(command, timeout=90)
    if res.exit_code != 0 and not res.stdout:
        return json.dumps({"ok": False, "error": f"replay failed (exit {res.exit_code}): "
                                                 f"{res.stderr[:300]}"})
    # curl -i: status line + headers + body — hand the model the lot, truncated.
    output = res.stdout
    if res.stderr.strip():
        output += f"\n[curl stderr] {res.stderr.strip()[:200]}"
    return json.dumps({
        "ok": True,
        "replayed": {"id": rid, "method": method, "url": url},
        "note": "re-issued from the sandbox through the scanning proxy "
                "(scope-enforced); response below",
        "response": truncate(output, 8000),
    }, ensure_ascii=False)


def _tool_view_sitemap(ctx, _args: dict[str, Any]) -> str:
    refused = _no_proxy(ctx)
    if refused:
        return refused
    flows = _flows(ctx)
    tree: dict[str, dict[str, dict[str, set[str]]]] = {}
    for rec in flows:
        host = rec.get("host") or "?"
        path = (rec.get("path") or "/").split("?", 1)[0] or "/"
        node = tree.setdefault(host, {}).setdefault(path, {"methods": set(), "statuses": set()})
        node["methods"].add(rec.get("method") or "?")
        if rec.get("status"):
            node["statuses"].add(str(rec["status"]))
    lines = [f"{len(flows)} proxied requests mapped."]
    for host in sorted(tree):
        lines.append(f"\n{host}")
        for path in sorted(tree[host])[:200]:
            node = tree[host][path]
            methods = ",".join(sorted(node["methods"]))
            statuses = ",".join(sorted(node["statuses"]))
            lines.append(f"  [{methods}] {path}  -> {statuses}")
    if len(lines) > 210:
        lines.append("  ... (sitemap truncated)")
    return json.dumps({"ok": True, "sitemap": truncate("\n".join(lines), 8000)},
                      ensure_ascii=False)


# -- schemas -----------------------------------------------------------------------

def _fn(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


PROXY_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_requests": _fn(
        "list_requests",
        "List HTTP requests captured by the scanning proxy (everything the scan "
        "sent through it — your curl/browser traffic included). Filter by "
        "substring, method, or status. Returns ids for view_request/repeat_request.",
        {
            "q": {"type": "string", "description": "Substring matched against host+path."},
            "method": {"type": "string", "description": "Filter by HTTP method."},
            "status": {"type": "integer", "description": "Filter by response status code."},
            "limit": {"type": "integer", "description": "Max rows (default 30)."},
        },
        [],
    ),
    "view_request": _fn(
        "view_request",
        "Show one captured request/response in full: headers, bodies, timing. "
        "Authorization/Cookie values are redacted in the log; use repeat_request "
        "to replay with the authenticated session.",
        {"id": {"type": "integer", "description": "Request id from list_requests."}},
        ["id"],
    ),
    "repeat_request": _fn(
        "repeat_request",
        "Re-issue a captured request with optional modifications (method, url, "
        "body). Runs from the sandbox THROUGH the scanning proxy with the live "
        "authenticated session — scope is enforced at the network layer, exactly "
        "like the original request. Ideal for parameter replay and PoC confirmation.",
        {
            "id": {"type": "integer", "description": "Request id from list_requests."},
            "modifications": {
                "type": "object",
                "description": "Optional overrides for the replay.",
                "properties": {
                    "method": {"type": "string"},
                    "url": {"type": "string", "description": "Full replacement URL (must be in scope)."},
                    "body": {"type": "string", "description": "Replacement request body."},
                },
                "additionalProperties": False,
            },
        },
        ["id"],
    ),
    "view_sitemap": _fn(
        "view_sitemap",
        "Aggregate sitemap of everything the proxy captured: host -> paths with "
        "methods and response statuses. The consolidated attack-surface map of "
        "traffic the scan actually exercised.",
        {},
        [],
    ),
}

PROXY_TOOL_NAMES = set(PROXY_SCHEMAS)

PROXY_HANDLERS = {
    "list_requests": _tool_list_requests,
    "view_request": _tool_view_request,
    "repeat_request": _tool_repeat_request,
    "view_sitemap": _tool_view_sitemap,
}
