"""Browser tools: stateful headless-Chromium sessions, one per agent.

The heavy lifting (Playwright, Chromium) lives in ``browser_daemon.py``,
shipped into the sandbox and started lazily on the first browser tool call.
Host-side we only ship JSON commands via localhost curl through sandbox exec
and pull screenshots back with docker get_archive — so everything here is
plain sync code that runs in the session's worker-thread dispatch, matching
the other hands-on tools.

Scope: navigate/click/fill targets are host-checked against the scan scope
before they ever reach Chromium (the proxy allowlist and the lab network
remain the deeper layers). Out-of-scope attempts are refused AND logged to
the transcript.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from vulnem.textutil import truncate

logger = logging.getLogger(__name__)

DAEMON_PORT = 7788
DAEMON_PATH = "/home/pentester/.vulnem/browser_daemon.py"
CMD_FILE = "/tmp/.vulnem-browser-cmd.json"
ARTIFACT_SUBDIR = "artifacts"
SANITIZED_RE = re.compile(r"[^A-Za-z0-9._-]+")
# cold-start budget for chromium (tests shrink these via monkeypatching)
DAEMON_START_RETRIES = 30
DAEMON_START_DELAY = 1.0

# daemon lifecycle + per-agent cookie seeding, keyed by sandbox identity
_lock = threading.Lock()
_daemons_started: set[int] = set()
_seeded_agents: set[tuple[int, str]] = set()


def reset_daemon_state() -> None:
    """Test hook: forget started daemons / seeded agents for fresh sandboxes."""
    with _lock:
        _daemons_started.clear()
        _seeded_agents.clear()


def _sanitize_agent(name: str) -> str:
    return SANITIZED_RE.sub("_", (name or "default").strip()) or "default"


def host_in_scope(url: str, allowed_hosts: tuple[str, ...] | list[str]) -> bool:
    """True when the URL's host matches the system-verified scope list."""
    try:
        host = (urllib.parse.urlsplit(url.strip()).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    allowed = {h.lower() for h in allowed_hosts}
    return host in allowed


def _daemon_url() -> str:
    return f"http://127.0.0.1:{DAEMON_PORT}/"


def _ping(sandbox) -> dict | None:
    res = sandbox.exec(
        f"curl -s -m 3 -X POST -H 'Content-Type: application/json' -d '{{\"op\":\"ping\"}}' "
        f"{_daemon_url()}",
        timeout=10,
    )
    if res.exit_code != 0 or not res.stdout.strip():
        return None
    try:
        payload = json.loads(res.stdout)
    except ValueError:
        return None
    return payload if payload.get("ok") else None


def ensure_daemon(sandbox, proxy_url: str | None) -> str | None:
    """Make sure the browser daemon is up in this sandbox.

    Returns None on success or a human-readable error message. Idempotent
    per sandbox; safe to call from every browser tool invocation.
    """
    with _lock:
        if id(sandbox) in _daemons_started and _ping(sandbox) is not None:
            return None
        source = Path(__file__).with_name("browser_daemon.py").read_bytes()
        daemon_dir = DAEMON_PATH.rsplit("/", 1)[0]
        try:
            sandbox.exec(f"mkdir -p {daemon_dir}", timeout=15)  # put_archive needs the dir
            sandbox.put_file(source, DAEMON_PATH)
        except Exception as exc:
            return f"could not ship browser daemon into sandbox: {exc}"
        proxy_arg = f" --proxy {proxy_url}" if proxy_url else ""
        # Kill a stale daemon by pidfile (never pkill by name — this very
        # command line contains the daemon path), then start a fresh one.
        start = (
            "kill $(cat /tmp/browser-daemon.pid 2>/dev/null) 2>/dev/null; "
            f"nohup python3 {DAEMON_PATH} --port {DAEMON_PORT}"
            f"{proxy_arg} >/tmp/browser-daemon.log 2>&1 & "
            "echo $! > /tmp/browser-daemon.pid"
        )
        sandbox.exec(start, timeout=30)
        for _ in range(DAEMON_START_RETRIES):  # chromium cold start can take a few seconds
            if _ping(sandbox) is not None:
                _daemons_started.add(id(sandbox))
                return None
            time.sleep(DAEMON_START_DELAY)
        log = sandbox.exec("tail -20 /tmp/browser-daemon.log", timeout=10).stdout
        hint = log.strip()[-500:] or (
            "no output — is playwright installed? the sandbox image may need "
            "a rebuild: vulnem build"
        )
        return f"browser daemon failed to start (see /tmp/browser-daemon.log in the sandbox): {hint}"


def daemon_op(sandbox, op: dict, *, proxy_url: str | None = None,
              timeout_s: int = 90) -> dict:
    """Low-level: run one daemon operation (also used by the auth flow)."""
    error = ensure_daemon(sandbox, proxy_url)
    if error:
        return {"ok": False, "error": error}
    try:
        payload = json.dumps(op, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        return {"ok": False, "error": f"unserializable op: {exc}"}
    try:
        sandbox.put_file(payload, CMD_FILE)
    except Exception as exc:
        return {"ok": False, "error": f"could not stage command file: {exc}"}
    res = sandbox.exec(
        f"curl -s -m {max(5, int(timeout_s))} -X POST "
        f"-H 'Content-Type: application/json' --data-binary @{CMD_FILE} {_daemon_url()}",
        timeout=timeout_s + 15,
    )
    try:
        return json.loads(res.stdout)
    except ValueError:
        return {
            "ok": False,
            "error": f"daemon returned non-JSON (exit {res.exit_code}): "
                     f"{res.stdout[:200] or res.stderr[:200]}",
        }


def _seed_auth_cookies(ctx, agent: str) -> None:
    """Inject the scan's authenticated session into a fresh agent context."""
    cookies = list(getattr(ctx, "auth_cookies", None) or [])
    if not cookies:
        return
    key = (id(ctx.sandbox), agent)
    with _lock:
        if key in _seeded_agents:
            return
        _seeded_agents.add(key)
    daemon_op(ctx.sandbox, {"agent": agent, "op": "set_cookies", "cookies": cookies},
              proxy_url=getattr(ctx, "sandbox_proxy_url", None))


def _browser_op(ctx, op: dict, timeout_s: int = 90) -> str:
    agent = ctx.agent_name or "default"
    error = ensure_daemon(ctx.sandbox, getattr(ctx, "sandbox_proxy_url", None))
    if error:
        return json.dumps({"ok": False, "error": error})
    _seed_auth_cookies(ctx, agent)
    result = daemon_op(ctx.sandbox, {"agent": agent, **op}, timeout_s=timeout_s)
    return json.dumps(result, ensure_ascii=False)


def _scope_guard(ctx, url: str) -> str | None:
    """Refuse + log out-of-scope browser targets before they reach Chromium."""
    if host_in_scope(url, getattr(ctx, "allowed_hosts", ()) or ()):
        return None
    event = {
        "type": "scope_blocked",
        "layer": "browser-tool",
        "url": url[:300],
        "detail": "browser navigation outside the system-verified scope was refused",
    }
    emit = getattr(ctx, "emit_event", None)
    if emit is not None:
        emit(event)
    logger.warning("blocked out-of-scope browser navigation: %s", url[:200])
    return json.dumps({
        "ok": False,
        "error": "OUT OF SCOPE: the browser refuses to navigate to hosts outside "
                 "the system-verified scope. This attempt was logged.",
    })


# -- tool handlers (sync, run in worker threads) --------------------------------


def _tool_browser_navigate(ctx, args: dict[str, Any]) -> str:
    url = str(args.get("url") or "").strip()
    if not url:
        return json.dumps({"ok": False, "error": "url is required"})
    refused = _scope_guard(ctx, url)
    if refused:
        return refused
    return _browser_op(ctx, {"op": "navigate", "url": url,
                             "timeout_ms": int(args.get("timeout_s") or 45) * 1000},
                       timeout_s=int(args.get("timeout_s") or 45) + 15)


def _tool_browser_click(ctx, args: dict[str, Any]) -> str:
    selector = str(args.get("selector") or "")
    if not selector:
        return json.dumps({"ok": False, "error": "selector is required"})
    return _browser_op(ctx, {"op": "click", "selector": selector,
                             "timeout_ms": int(args.get("timeout_s") or 20) * 1000},
                       timeout_s=int(args.get("timeout_s") or 20) + 20)


def _tool_browser_fill(ctx, args: dict[str, Any]) -> str:
    selector = str(args.get("selector") or "")
    if not selector:
        return json.dumps({"ok": False, "error": "selector is required"})
    if "value" not in args:
        return json.dumps({"ok": False, "error": "value is required"})
    return _browser_op(ctx, {"op": "fill", "selector": selector,
                             "value": str(args["value"]),
                             "timeout_ms": int(args.get("timeout_s") or 15) * 1000},
                       timeout_s=int(args.get("timeout_s") or 15) + 15)


def _tool_browser_read_page(ctx, _args: dict[str, Any]) -> str:
    result = json.loads(_browser_op(ctx, {"op": "read_page"}))
    if result.get("ok") and "text" in result:
        result["text"] = truncate(result["text"], 6000)
    return json.dumps(result, ensure_ascii=False)


def _tool_browser_evaluate(ctx, args: dict[str, Any]) -> str:
    expression = str(args.get("expression") or "")
    if not expression:
        return json.dumps({"ok": False, "error": "expression is required"})
    return _browser_op(ctx, {"op": "evaluate", "expression": expression}, timeout_s=45)


def _tool_browser_screenshot(ctx, args: dict[str, Any]) -> str:
    result = json.loads(_browser_op(ctx, {
        "op": "screenshot",
        "name": str(args.get("name") or "shot"),
        "full_page": bool(args.get("full_page")),
    }))
    if not result.get("ok"):
        return json.dumps(result, ensure_ascii=False)
    run_dir: Path | None = getattr(ctx, "run_dir", None)
    agent = _sanitize_agent(ctx.agent_name)
    rel_path = f"{ARTIFACT_SUBDIR}/{agent}/{Path(result['path']).name}"
    if run_dir is not None:
        try:
            png = ctx.sandbox.get_file(result["path"])
            out = run_dir / rel_path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(png)
            result["artifact"] = rel_path
            result["note"] = ("screenshot saved; reference it by this path in "
                              "finding evidence")
            emit = getattr(ctx, "emit_event", None)
            if emit is not None:
                emit({"type": "screenshot", "artifact": rel_path,
                      "bytes": len(png), "url": result.get("url", "")})
        except Exception as exc:
            result["artifact_error"] = f"screenshot taken but retrieval failed: {exc}"
    return json.dumps(result, ensure_ascii=False)


# -- schemas ----------------------------------------------------------------------

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


BROWSER_SCHEMAS: dict[str, dict[str, Any]] = {
    "browser_navigate": _fn(
        "browser_navigate",
        "Navigate YOUR headless-Chromium session (state is kept per agent: cookies, "
        "localStorage, page history) to a URL. Renders JavaScript, then returns the "
        "final URL, HTTP status, and page title. Use for JS-heavy pages, SPA routes, "
        "and anything curl cannot render. Scope is enforced.",
        {
            "url": {"type": "string", "description": "Absolute URL (in scope)."},
            "timeout_s": {"type": "integer", "description": "Optional load timeout (default 45s)."},
        },
        ["url"],
    ),
    "browser_click": _fn(
        "browser_click",
        "Click an element in your browser session by CSS selector. Waits for the "
        "element to be visible. Returns the resulting URL/title.",
        {
            "selector": {"type": "string", "description": "CSS selector of the element."},
            "timeout_s": {"type": "integer"},
        },
        ["selector"],
    ),
    "browser_fill": _fn(
        "browser_fill",
        "Type a value into a form field in your browser session (clears it first).",
        {
            "selector": {"type": "string", "description": "CSS selector of input/textarea."},
            "value": {"type": "string", "description": "Text to type (payloads welcome)."},
            "timeout_s": {"type": "integer"},
        },
        ["selector", "value"],
    ),
    "browser_read_page": _fn(
        "browser_read_page",
        "Read the current page of your browser session: URL, title, visible text, "
        "link inventory, form/input inventory, and any dialogs (alert/confirm) "
        "triggered so far. Dialogs recorded here are executable XSS proof.",
        {},
        [],
    ),
    "browser_evaluate": _fn(
        "browser_evaluate",
        "Evaluate a JavaScript expression in the current page of your browser "
        "session and return the JSON result. Use to read DOM state, test payload "
        "effects (e.g. marker variables set by onerror handlers), and inspect "
        "client-side logic.",
        {"expression": {"type": "string", "description": "JS expression to evaluate."}},
        ["expression"],
    ),
    "browser_screenshot": _fn(
        "browser_screenshot",
        "Capture the current page of your browser session as a PNG. The screenshot "
        "is saved into the run's artifacts and can be cited as finding evidence.",
        {
            "name": {"type": "string", "description": "Optional file base name."},
            "full_page": {"type": "boolean", "description": "Capture full scroll height."},
        },
        [],
    ),
}

BROWSER_TOOL_NAMES = set(BROWSER_SCHEMAS)

BROWSER_HANDLERS = {
    "browser_navigate": _tool_browser_navigate,
    "browser_click": _tool_browser_click,
    "browser_fill": _tool_browser_fill,
    "browser_read_page": _tool_browser_read_page,
    "browser_evaluate": _tool_browser_evaluate,
    "browser_screenshot": _tool_browser_screenshot,
}
