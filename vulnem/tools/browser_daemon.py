#!/usr/bin/env python3
"""Stateful headless-Chromium daemon — runs INSIDE the sandbox container.

The host browser tools (vulnem/tools/browser.py) ship this file into the
sandbox and talk to it over localhost HTTP with JSON payloads (one request
per tool call, via ``curl`` through sandbox exec).

One browser process, one isolated context per agent name: parallel
specialists each get their own cookies/storage so they never stomp each
other. Dialogs (alert/confirm/prompt) are auto-dismissed and RECORDED per
session — a recorded dialog is executable proof of an XSS payload.

Requests look like::

    {"agent": "xss-probe", "op": "navigate", "url": "http://target/x"}

and every response is JSON with an ``ok`` flag. Screenshots are written
under /home/pentester/artifacts/<agent>/ inside the container; the host
pulls them out with docker get_archive into runs/<id>/artifacts/.

Usage: python3 browser_daemon.py [--proxy http://host:port] [--port 7788]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ARTIFACT_ROOT = "/home/pentester/artifacts"
MAX_PAGE_TEXT = 6000
MAX_LINKS = 60
MAX_INPUTS = 60
DEFAULT_NAV_TIMEOUT_MS = 45_000
SANITIZED_AGENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


class BrowserSessions:
    """Owns the Playwright browser + one context per agent."""

    def __init__(self, proxy: str | None) -> None:
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        launch_args = [
            "--no-sandbox",  # container isolation is the boundary; user is non-root
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ]
        self._browser = self._pw.chromium.launch(headless=True, args=launch_args)
        self._proxy = proxy
        self._sessions: dict[str, dict] = {}
        self.started_at = time.time()

    # -- session management ---------------------------------------------------

    def _session(self, agent: str) -> dict:
        agent = SANITIZED_AGENT_RE.sub("_", agent or "default") or "default"
        if agent not in self._sessions:
            kwargs = {"ignore_https_errors": True}
            if self._proxy:
                kwargs["proxy"] = {"server": self._proxy}
            context = self._browser.new_context(**kwargs)
            page = context.new_page()
            session = {"context": context, "page": page, "dialogs": [], "url": "about:blank"}
            # Auto-dismiss dialogs and keep them as evidence (XSS execution proof).
            page.on("dialog", lambda dialog: self._on_dialog(session, dialog))
            self._sessions[agent] = session
        return self._sessions[agent]

    @staticmethod
    def _on_dialog(session: dict, dialog) -> None:
        entry = {
            "type": dialog.type,
            "message": dialog.message[:500],
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "url": session.get("url", ""),
        }
        session["dialogs"].append(entry)
        with contextlib.suppress(Exception):
            dialog.dismiss()

    def close_session(self, agent: str) -> None:
        session = self._sessions.pop(agent, None)
        if session:
            with contextlib.suppress(Exception):
                session["context"].close()

    def shutdown(self) -> None:
        for agent in list(self._sessions):
            self.close_session(agent)
        try:
            self._browser.close()
            self._pw.stop()
        except Exception:
            pass

    # -- operations -------------------------------------------------------------

    def op(self, req: dict) -> dict:
        agent = str(req.get("agent") or "default")
        op = str(req.get("op") or "")
        session = self._session(agent)
        page = session["page"]
        timeout = int(req.get("timeout_ms") or DEFAULT_NAV_TIMEOUT_MS)

        if op == "navigate":
            url = str(req.get("url") or "")
            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            page.wait_for_load_state("networkidle", timeout=5000)
            session["url"] = page.url
            return {
                "ok": True,
                "url": page.url,
                "status": resp.status if resp else None,
                "title": page.title(),
            }

        if op == "click":
            selector = str(req.get("selector") or "")
            page.click(selector, timeout=timeout)
            page.wait_for_load_state("networkidle", timeout=5000)
            session["url"] = page.url
            return {"ok": True, "url": page.url, "title": page.title()}

        if op == "fill":
            selector = str(req.get("selector") or "")
            value = str(req.get("value") or "")
            page.fill(selector, value, timeout=timeout)
            return {"ok": True}

        if op == "read_page":
            return self._read_page(session)

        if op == "evaluate":
            expression = str(req.get("expression") or "null")
            value = page.evaluate(expression)
            return {"ok": True, "result": _json_safe(value)}

        if op == "screenshot":
            name = SANITIZED_AGENT_RE.sub("_", str(req.get("name") or "")) or "shot"
            if not name.endswith(".png"):
                name += ".png"
            out_dir = f"{ARTIFACT_ROOT}/{SANITIZED_AGENT_RE.sub('_', agent) or 'default'}"
            import os

            os.makedirs(out_dir, exist_ok=True)
            path = f"{out_dir}/{int(time.time() * 1000)}-{name}"
            page.screenshot(
                path=path,
                full_page=bool(req.get("full_page")),
                timeout=max(timeout, 20_000),
            )
            return {"ok": True, "path": path}

        if op == "set_cookies":
            cookies = req.get("cookies") or []
            session["context"].add_cookies(cookies)
            return {"ok": True, "n": len(cookies)}

        if op == "get_cookies":
            return {"ok": True, "cookies": session["context"].cookies()}

        if op == "get_dialogs":
            return {"ok": True, "dialogs": session["dialogs"]}

        if op == "clear_dialogs":
            session["dialogs"] = []
            return {"ok": True}

        if op == "close":
            self.close_session(agent)
            return {"ok": True}

        return {"ok": False, "error": f"unknown op {op!r}"}

    def _read_page(self, session: dict) -> dict:
        page = session["page"]
        session["url"] = page.url
        title = page.title()
        try:
            text = page.inner_text("body")
        except Exception:
            text = re.sub(r"<[^>]+>", " ", page.content() or "")
            text = re.sub(r"\s+", " ", text).strip()
        links = page.eval_on_selector_all(
            "a[href]",
            "els => els.slice(0, 80).map(e => ({href: e.href, text: (e.innerText || '').trim().slice(0, 60)}))",
        )
        inputs = page.eval_on_selector_all(
            "input, select, textarea",
            "els => els.slice(0, 80).map(e => ({tag: e.tagName.toLowerCase(), "
            "type: (e.type || ''), name: (e.name || ''), id: (e.id || ''), "
            "placeholder: (e.placeholder || '').slice(0, 40)}))",
        )
        return {
            "ok": True,
            "url": page.url,
            "title": title,
            "text": (text or "")[:MAX_PAGE_TEXT],
            "links": [
                {"href": str(link.get("href", ""))[:300], "text": str(link.get("text", ""))[:60]}
                for link in links[:MAX_LINKS]
            ],
            "inputs": inputs[:MAX_INPUTS],
            "dialogs": session["dialogs"],
        }

    def ping(self) -> dict:
        return {
            "ok": True,
            "chromium": True,
            "uptime_s": int(time.time() - self.started_at),
            "sessions": sorted(self._sessions),
        }


def _json_safe(value):
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)


class Handler(BaseHTTPRequestHandler):
    sessions: BrowserSessions | None = None

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(length) or b"{}")
            if req.get("op") == "ping":
                payload = self.sessions.ping() if self.sessions else {"ok": False, "error": "starting"}
            else:
                payload = self.sessions.op(req)
        except Exception as exc:  # every failure is a JSON error, never a hang
            payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # keep the daemon quiet
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=7788)
    parser.add_argument("--proxy", default=None, help="upstream proxy for all contexts")
    args = parser.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), Handler)
    Handler.sessions = BrowserSessions(args.proxy)
    print(f"browser-daemon up on 127.0.0.1:{args.port} proxy={args.proxy}", flush=True)
    try:
        server.serve_forever()
    finally:
        Handler.sessions.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
