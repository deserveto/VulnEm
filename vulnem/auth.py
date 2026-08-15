"""Authenticated scans: operator credentials -> ready session, no secrets in prompts.

The operator passes ``--creds <file>`` (JSON, never committed for real
targets). The HOST reads it, establishes the session against the target
BEFORE any agent runs (browser form login, API login, or raw cookies), and
hands agents only the resulting cookie session:

- browser_* tools seed every agent's Chromium context with the cookies;
- curl-based work uses ``/home/pentester/cookies.txt`` in the sandbox
  (``-b /home/pentester/cookies.txt``);
- the login runs through the scanning proxy, so it is scope-checked and
  captured like any other request.

Credential VALUES never enter an LLM context, a prompt, or the transcript —
only cookie names and the login method are recorded.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

COOKIE_JAR_PATH = "/home/pentester/cookies.txt"
HEADER_FILE_PATH = "/home/pentester/.vulnem/auth-header.txt"
AUTH_AGENT = "vulnem-auth"


class CredsError(ValueError):
    """Malformed or unusable credentials file."""


@dataclass(slots=True)
class CredsConfig:
    """Parsed credentials file. Values stay on the host, never in prompts."""

    login_url: str = ""
    method: str = "browser"  # browser | api | cookies
    username: str = ""
    password: str = ""
    username_selector: str = 'input[name="username"], input[name="email"], input[type="email"]'
    password_selector: str = 'input[name="password"], input[type="password"]'
    submit_selector: str = 'button[type="submit"], input[type="submit"], button:has-text("log in"), button:has-text("sign in"), button:has-text("Login")'
    api: dict[str, Any] = field(default_factory=dict)  # {method,url,headers,json|body}
    cookies: list[dict[str, str]] = field(default_factory=list)
    setup: dict[str, str] = field(default_factory=dict)  # {url, click} run BEFORE login
    verify_selector: str = ""  # element expected post-login (optional sanity check)

    @classmethod
    def load(cls, path: str | Path) -> CredsConfig:
        path = Path(path)
        if not path.is_file():
            raise CredsError(f"credentials file not found: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise CredsError(f"credentials file is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise CredsError("credentials file must be a JSON object")
        cfg = cls(
            login_url=str(data.get("login_url") or ""),
            method=str(data.get("method") or "browser").lower(),
            username=str(data.get("username") or ""),
            password=str(data.get("password") or ""),
            api=data.get("api") or {},
            cookies=data.get("cookies") or [],
            setup=data.get("setup") or {},
            verify_selector=str(data.get("verify_selector") or ""),
        )
        for key in ("username_selector", "password_selector", "submit_selector"):
            if data.get(key):
                setattr(cfg, key, str(data[key]))
        if cfg.method not in {"browser", "api", "cookies"}:
            raise CredsError(f"method must be browser|api|cookies, got {cfg.method!r}")
        if cfg.method == "browser" and not cfg.login_url:
            raise CredsError("method 'browser' requires login_url")
        if cfg.method == "api" and not (cfg.api.get("url") or cfg.login_url):
            raise CredsError("method 'api' requires api.url or login_url")
        if cfg.method == "cookies" and not cfg.cookies:
            raise CredsError("method 'cookies' requires a cookies list")
        return cfg

    def secret_names(self) -> list[str]:
        """Field names that hold secrets (for accidental-leak audits)."""
        return ["username", "password"]


@dataclass(slots=True)
class AuthResult:
    ok: bool
    method: str = ""
    detail: str = ""
    cookies: list[dict[str, Any]] = field(default_factory=list)  # playwright format
    cookie_names: list[str] = field(default_factory=list)
    bearer: str = ""                       # bearer token (never logged)
    storage: list[dict[str, str]] = field(default_factory=list)  # localStorage entries
    origin: str = ""                       # origin the storage/cookies belong to

    def describe(self) -> dict[str, Any]:
        """Transcript-safe summary — cookie NAMES + storage keys only."""
        return {
            "ok": self.ok,
            "method": self.method,
            "detail": self.detail[:300],
            "cookie_names": self.cookie_names,
            "has_bearer": bool(self.bearer),
            "storage_keys": [s.get("key") for s in self.storage],
        }


class AuthSession:
    """Establishes the authenticated session from the creds file."""

    def __init__(self, creds: CredsConfig) -> None:
        self.creds = creds

    def establish(self, *, sandbox, proxy_url: str | None = None) -> AuthResult:
        if self.creds.method == "cookies":
            cookies = _normalize_cookie_list(self.creds.cookies)
            return AuthResult(ok=True, method="cookies",
                              detail=f"{len(cookies)} operator-provided cookies",
                              cookies=cookies, cookie_names=[c["name"] for c in cookies],
                              origin=_origin_of(self.creds.login_url))
        if self.creds.method == "api":
            return self._via_api(sandbox)
        return self._via_browser(sandbox, proxy_url)

    # -- browser form login ---------------------------------------------------

    def _via_browser(self, sandbox, proxy_url: str | None) -> AuthResult:
        from vulnem.tools.browser import daemon_op

        creds = self.creds

        def op(payload: dict, timeout_s: int = 45) -> dict:
            return daemon_op(sandbox, {"agent": AUTH_AGENT, **payload},
                             proxy_url=proxy_url, timeout_s=timeout_s)

        if creds.setup.get("url"):
            setup = op({"op": "navigate", "url": creds.setup["url"]})
            if not setup.get("ok"):
                return AuthResult(ok=False, method="browser",
                                  detail=f"setup step failed: {setup.get('error')}")
            if creds.setup.get("click"):
                op({"op": "click", "selector": creds.setup["click"]}, timeout_s=30)
            time.sleep(2.0)  # let setup/db resets settle before logging in

        nav = op({"op": "navigate", "url": creds.login_url})
        if not nav.get("ok"):
            return AuthResult(ok=False, method="browser",
                              detail=f"could not load login page: {nav.get('error')}")
        for selector, value, label in (
            (creds.username_selector, creds.username, "username"),
            (creds.password_selector, creds.password, "password"),
        ):
            for one in selector.split(","):
                one = one.strip()
                if not one:
                    continue
                filled = op({"op": "fill", "selector": one, "value": value}, timeout_s=20)
                if filled.get("ok"):
                    break
            else:
                return AuthResult(ok=False, method="browser",
                                  detail=f"could not fill {label} field "
                                         f"(selector {selector!r})")
        for one in creds.submit_selector.split(","):
            one = one.strip()
            if not one:
                continue
            clicked = op({"op": "click", "selector": one}, timeout_s=30)
            if clicked.get("ok"):
                break
        else:
            return AuthResult(ok=False, method="browser",
                              detail=f"could not click submit (selector {creds.submit_selector!r})")
        time.sleep(3.0)  # SPA logins settle asynchronously
        state = op({"op": "read_page"})
        cookies = op({"op": "get_cookies"}).get("cookies") or []
        storage = op({"op": "get_storage"}).get("storage") or []
        session_cookies = _session_cookies(cookies)
        origin = _origin_of(creds.login_url)
        detail = f"login form submitted at {creds.login_url}; landed on " \
                 f"{str(state.get('url'))[:120]}"
        if not session_cookies and not storage:
            return AuthResult(ok=False, method="browser",
                              detail=detail + " — but no session cookies or storage "
                                   "were set (check credentials/selectors)")
        return AuthResult(ok=True, method="browser", detail=detail, origin=origin,
                          cookies=cookies, cookie_names=[c["name"] for c in cookies],
                          storage=storage)

    # -- API login ---------------------------------------------------------------

    def _via_api(self, sandbox) -> AuthResult:
        import shlex

        api = dict(self.creds.api)
        url = str(api.get("url") or self.creds.login_url)
        method = str(api.get("method") or "POST").upper()
        headers = dict(api.get("headers") or {})
        body = None
        if "json" in api:
            headers.setdefault("Content-Type", "application/json")
            body = json.dumps(api["json"])
        elif "body" in api:
            body = str(api["body"])
        parts = [f"curl -s -i -m 30 -X {shlex.quote(method)} {shlex.quote(url)}"]
        for name, value in headers.items():
            parts.append(f"-H {shlex.quote(f'{name}: {value}')}")
        if body is not None:
            sandbox.put_file(body.encode("utf-8"), "/tmp/.vulnem-login.json")
            parts.append("--data-binary @/tmp/.vulnem-login.json")
        res = sandbox.exec(" ".join(parts), timeout=60)
        if res.exit_code != 0 and not res.stdout:
            return AuthResult(ok=False, method="api",
                              detail=f"login request failed (exit {res.exit_code}): "
                                     f"{res.stderr[:200]}")
        cookies = _parse_set_cookies(res.stdout, url)
        bearer = _extract_bearer(res.stdout,
                                 str(api.get("token_json_path") or "token"))
        if bearer:
            # Token-auth SPAs typically ALSO expect the token as a cookie
            # (e.g. Juice Shop's `token` cookie); stage it for both transports.
            cookie_key = str(api.get("token_cookie_key") or "token")
            host = urllib.parse.urlsplit(url).hostname or ""
            if cookie_key and not any(c["name"] == cookie_key for c in cookies):
                cookies.append({"name": cookie_key, "value": bearer,
                                "domain": host, "path": "/"})
        if not cookies and not bearer:
            return AuthResult(ok=False, method="api",
                              detail=f"login to {url} set no cookies and no token — "
                                     f"check credentials (response head: {res.stdout[:200]!r})")
        what = []
        if cookies:
            what.append(f"{len(cookies)} cookie(s)")
        if bearer:
            what.append("bearer token")
        return AuthResult(ok=True, method="api",
                          detail=f"API login to {url} set " + " and ".join(what),
                          origin=_origin_of(url),
                          cookies=cookies, cookie_names=[c["name"] for c in cookies],
                          bearer=bearer)


# -- cookie helpers --------------------------------------------------------------


def _origin_of(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def _extract_bearer(raw_response: str, json_path: str) -> str:
    """Pull a bearer token out of a JSON response body (curl -i output)."""
    body = raw_response.split("\r\n\r\n", 1)[-1].split("\n\n", 1)[-1]
    try:
        data = json.loads(body.strip())
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    token = data.get(json_path)
    if isinstance(token, str) and token:
        return token
    # one nesting level of {auth: {token: ...}} style paths
    key = json_path.split(".")[-1]
    for value in data.values():
        if isinstance(value, dict) and isinstance(value.get(key), str):
            return value[key]
    return ""


def _session_cookies(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter to cookies that plausibly carry a session (non-ephemeral)."""
    out = []
    for c in cookies:
        name = (c.get("name") or "").lower()
        if name in {"", "csrf-token-anonymous"}:
            continue
        out.append(c)
    return out


def _normalize_cookie_list(cookies: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Operator-supplied cookie list -> playwright add_cookies format."""
    out: list[dict[str, Any]] = []
    for c in cookies:
        name, value = str(c.get("name") or ""), str(c.get("value") or "")
        if not name:
            continue
        out.append({
            "name": name,
            "value": value,
            "domain": str(c.get("domain") or ""),
            "path": str(c.get("path") or "/"),
        })
    return out


def _parse_set_cookies(raw_response: str, url: str) -> list[dict[str, Any]]:
    """Pull cookies out of a curl -i response (Set-Cookie headers)."""
    host = urllib.parse.urlsplit(url).hostname or ""
    cookies: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in raw_response.splitlines():
        if not line.lower().startswith("set-cookie:"):
            continue
        payload = line.split(":", 1)[1].strip()
        first = payload.split(";", 1)[0]
        if "=" not in first:
            continue
        name, _, value = first.partition("=")
        name, value = name.strip(), value.strip()
        if not name or (name, value) in seen:
            continue
        seen.add((name, value))
        attrs = {k.strip().lower(): v.strip() for k, _, v in
                 (p.partition("=") for p in payload.split(";")[1:])}
        cookies.append({
            "name": name,
            "value": value,
            "domain": attrs.get("domain", host).lstrip("."),
            "path": attrs.get("path", "/"),
        })
    return cookies


def cookies_to_netscape(cookies: list[dict[str, Any]]) -> str:
    """Render cookies as a Netscape cookies.txt jar for curl."""
    lines = ["# Netscape HTTP Cookie File (vulnem authenticated session)"]
    far_future = int(time.time()) + 86400
    for c in cookies:
        domain = (c.get("domain") or "").lstrip(".")
        include_sub = "TRUE" if domain and not domain.startswith(".") else "FALSE"
        secure = "TRUE" if str(c.get("secure", "")).lower() == "true" else "FALSE"
        http_only = "#HttpOnly_" if str(c.get("httpOnly", "")).lower() == "true" else ""
        lines.append("\t".join([
            http_only + domain,
            include_sub,
            c.get("path") or "/",
            secure,
            str(int(c.get("expires", 0) or far_future) or far_future),
            c.get("name") or "",
            c.get("value") or "",
        ]))
    return "\n".join(lines) + "\n"


def stage_session(sandbox, auth: AuthResult) -> None:
    """Write the curl-side session artifacts into the sandbox.

    - ``/home/pentester/cookies.txt`` — Netscape jar (``-b``)
    - ``/home/pentester/.vulnem/auth-header.txt`` — ``Authorization: Bearer``
      header file for ``curl -H @`` (apps that authenticate by token)
    Values stay inside the sandbox; agents reference the files, never the
    secrets themselves.
    """
    if not auth.ok:
        return
    try:
        if auth.cookies:
            sandbox.put_file(cookies_to_netscape(auth.cookies).encode("utf-8"),
                             COOKIE_JAR_PATH)
        if auth.bearer:
            sandbox.exec("mkdir -p /home/pentester/.vulnem", timeout=15)
            sandbox.put_file(f"Authorization: Bearer {auth.bearer}\n".encode(),
                             HEADER_FILE_PATH)
    except Exception:
        logger.exception("could not stage session artifacts into sandbox")
