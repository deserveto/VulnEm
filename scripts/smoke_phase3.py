"""Phase 3 plumbing smoke test: real Docker, no LLM.

Brings up Juice Shop on an internal network, the mitmproxy sidecar, and the
sandbox (routed through the proxy), then exercises:
  1. exec'd curl through the proxy -> flow captured in the sidecar log
  2. out-of-scope request -> BLOCKED (403) + logged
  3. browser daemon: navigate, read_page, screenshot (pulled back to host)
  4. proxy readers: flows/blocked via get_archive

Usage: .venv/Scripts/python scripts/smoke_phase3.py
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import docker  # noqa: E402

from vulnem.proxy.manager import ProxyManager  # noqa: E402
from vulnem.sandbox.docker import Sandbox  # noqa: E402
from vulnem.scope import Scope  # noqa: E402
from vulnem.tools import browser  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = ""):
    (PASS if ok else FAIL).append(name)
    print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f" — {detail}" if detail and not ok else ""))


def main() -> int:
    client = docker.from_env()
    net_name = f"vulnem-smoke-{uuid.uuid4().hex[:6]}"
    network = client.networks.create(net_name, driver="bridge", internal=True)
    juice = client.containers.run("bkimminich/juice-shop:latest",
                                  name=f"{net_name}-juice-shop",
                                  network=net_name, detach=True)
    target = f"http://{net_name}-juice-shop:3000"
    scope = Scope.from_target(target)
    pm = ProxyManager(scope=scope, network=net_name)
    sb = Sandbox(image="vulnem-sandbox:latest", user="pentester",
                 network=net_name, proxy_url=pm.sandbox_proxy_url)
    try:
        pm.start()
        print(f"sidecar {pm.name} up; target {target}")
        sb.start()
        for _ in range(60):
            if sb.exec(f"curl -sf -o /dev/null -m 5 {target}", timeout=30).exit_code == 0:
                break
            time.sleep(2)
        else:
            print("target never came up")
            return 2

        # 1. proxied curl is captured
        res = sb.exec(f"curl -s -o /dev/null -w '%{{http_code}}' {target}/rest/products/search?q=smoke",
                      timeout=60)
        time.sleep(1.5)
        flows = pm.read_flows()
        check("proxied curl captured in flow log",
              any("/rest/products/search" in (f.get("path") or "") for f in flows),
              f"flows={[f.get('path') for f in flows]}")
        check("curl exit 0 through proxy", res.exit_code == 0, res.stdout)

        # 2. out-of-scope is blocked + logged
        res = sb.exec("curl -s -m 10 -o /dev/null -w '%{http_code}' http://evil.invalid/x", timeout=30)
        blocked = pm.read_blocked()
        check("out-of-scope request returns 403", res.stdout.strip() == "403", f"got {res.stdout!r}")
        check("out-of-scope attempt logged", any(b.get("host") == "evil.invalid" for b in blocked),
              f"blocked={blocked}")

        # 3. browser daemon through the proxy
        nav = browser.daemon_op(sb, {"agent": "smoke", "op": "navigate", "url": target},
                                proxy_url=pm.sandbox_proxy_url, timeout_s=90)
        check("browser navigate (real Chromium, proxied)", nav.get("ok") is True, str(nav)[:200])
        page = browser.daemon_op(sb, {"agent": "smoke", "op": "read_page"},
                                 proxy_url=pm.sandbox_proxy_url)
        check("read_page returns title/text", page.get("ok") and "Juice" in (page.get("title") or ""),
              str(page)[:200])
        shot = browser.daemon_op(sb, {"agent": "smoke", "op": "screenshot", "name": "smoke"},
                                 proxy_url=pm.sandbox_proxy_url)
        png = sb.get_file(shot.get("path", "")) if shot.get("ok") else b""
        check("screenshot taken + pulled to host", png[:8] == b"\x89PNG\r\n\x1a\n",
              f"shot={shot}")
        time.sleep(1.5)
        flows = pm.read_flows()
        check("browser traffic also captured by proxy", len(flows) >= 3,
              f"n_flows={len(flows)}")

        # 4. manager snapshot evidence
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            pm.snapshot_evidence(Path(td))
            n = len((Path(td) / "proxy-flows.jsonl").read_text().splitlines())
            check("evidence snapshot written", n >= 3, f"n={n}")

        print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
        return 0 if not FAIL else 2
    finally:
        sb.stop()
        pm.stop()
        juice.remove(force=True, v=True)
        network.remove()


if __name__ == "__main__":
    sys.exit(main())
