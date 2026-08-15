"""VulnApp — VulnEm's deliberately vulnerable demo target (white-box + evals).

Stdlib-only on purpose: builds anywhere, no pip, and every flaw below is
PLANTED and documented in evals/ground_truth/vuln-app.json:

  /search?q=       SQL injection (sqlite f-string) + reflected XSS (raw echo)
  /note?name=      path traversal read (unsanitized join)
  /ping?host=      OS command injection (subprocess shell=True)
  /status          debug endpoint leaking the hardcoded API key
  /login           hardcoded credential check (admin / vulnem-admin-token)

Run: python server.py  (binds 0.0.0.0:5000)
"""

from __future__ import annotations

import html
import json
import os
import sqlite3
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# -- planted flaw: hardcoded secrets -----------------------------------------
API_KEY = "vk_9f3a1c7d55e8b2f0d4a6c8e0"          # noqa: S105 - planted
ADMIN_PASSWORD = "vulnem-admin-token"              # noqa: S105 - planted

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT,"
        " price REAL);"
        "INSERT OR IGNORE INTO products VALUES (1,'Widget',9.99),"
        "(2,'Gadget',19.99),(3,'Gizmo',29.99);"
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT,"
        " password TEXT);"
        "INSERT OR IGNORE INTO users VALUES (1,'admin','root-pw');"
    )
    conn.commit()
    conn.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # quiet
        pass

    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8") -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        url = urlsplit(self.path)
        params = parse_qs(url.query)
        route = url.path.rstrip("/") or "/"

        if route == "/":
            self._send(200, "<h1>VulnApp</h1><p>routes: /search /note /ping /status</p>")
        elif route == "/search":
            q = params.get("q", [""])[0]
            # planted flaw: SQL injection — user input concatenated into SQL
            rows: list = []
            err = ""
            conn = sqlite3.connect(DB_PATH)
            try:
                rows = conn.execute(
                    f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
                ).fetchall()
            except sqlite3.OperationalError as exc:
                err = str(exc)
            finally:
                conn.close()
            # planted flaw: reflected XSS — q echoed back without escaping
            body = (f"<html><body><h2>Results for: {q}</h2><ul>"
                    + "".join(f"<li>{r[1]} — ${r[2]}</li>" for r in rows)
                    + "</ul>"
                    + (f"<pre>{err}</pre>" if not rows else "")
                    + "</body></html>")
            self._send(200, body)
        elif route == "/note":
            name = params.get("name", [""])[0]
            base = os.path.join(os.path.dirname(__file__), "notes")
            # planted flaw: path traversal — unsanitized path join
            try:
                with open(os.path.join(base, name), encoding="utf-8") as fh:
                    self._send(200, f"<pre>{html.escape(fh.read())}</pre>")
            except OSError:
                self._send(404, "not found")
        elif route == "/ping":
            host = params.get("host", [""])[0]
            # planted flaw: command injection — user input through shell=True
            out = subprocess.run(  # noqa: S602 - planted
                f"ping -n 1 -w 1000 {host}", shell=True, capture_output=True,
                text=True, timeout=10,
            )
            self._send(200, f"<pre>{html.escape(out.stdout or out.stderr)}</pre>")
        elif route == "/status":
            # planted flaw: information disclosure — debug endpoint with secrets
            self._send(200, json.dumps({
                "ok": True, "db": DB_PATH, "api_key": API_KEY,
                "env": dict(os.environ),
            }), ctype="application/json")
        elif route == "/login":
            # planted flaw: hardcoded credentials + non-constant-time compare
            user = params.get("user", [""])[0]
            pw = params.get("pw", [""])[0]
            ok = user == "admin" and pw == ADMIN_PASSWORD
            self._send(200, json.dumps({"ok": ok}), ctype="application/json")
        else:
            self._send(404, "not found")


if __name__ == "__main__":
    init_db()
    os.makedirs(os.path.join(os.path.dirname(__file__), "notes"), exist_ok=True)
    notes = os.path.join(os.path.dirname(__file__), "notes", "readme.txt")
    if not os.path.exists(notes):
        with open(notes, "w", encoding="utf-8") as fh:
            fh.write("internal note: rotate the API key quarterly\n")
    ThreadingHTTPServer(("0.0.0.0", 5000), Handler).serve_forever()
