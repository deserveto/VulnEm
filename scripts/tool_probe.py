"""One-off harness: run the wrapped pentest tools inside the REAL sandbox +
scope-proxy stack (exactly like a scan) and print raw stdout/stderr.

Usage: .venv/Scripts/python scripts/tool_probe.py https://bursanalar.com/
"""
from __future__ import annotations

import sys

from vulnem.config import Settings
from vulnem.proxy.manager import ProxyManager
from vulnem.sandbox import Sandbox
from vulnem.sandbox.network import connect_container
from vulnem.scope import Scope

TOOLS = [
    "curl -sI {t}/ | head -3",
    "httpx -u {t}/ -status-code -title -silent",
    "katana -u {t}/ -d 2 -timeout 15 2>&1 | head -12",
    "katana -u {t}/ -d 1 -hl -silent 2>&1 | head -12",
    "nuclei -u {t}/ -tags tech -silent -stats 2>&1 | head -8",
]


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "https://bursanalar.com/"
    settings = Settings.load()
    scope = Scope.from_target(target)
    proxy = ProxyManager(scope=scope)
    sandbox = Sandbox(
        image=settings.sandbox_image, user=settings.sandbox_user,
        proxy_url=proxy.sandbox_proxy_url,
    )
    proxy.start()
    sandbox.start()
    if proxy.network and proxy.network != sandbox.network:
        connect_container(proxy.network, sandbox.container_name)
    try:
        ca = proxy.get_ca_cert()
        if ca:
            sandbox.install_proxy_ca(ca)
        for tpl in TOOLS:
            cmd = tpl.format(t=target.rstrip("/"))
            print(f"\n$ {cmd}", flush=True)
            r = sandbox.exec(cmd, timeout=240)
            print(f"  exit={r.exit_code} ({r.duration:.1f}s)")
            if r.stdout.strip():
                print("  stdout:", r.stdout.strip()[:600])
            if r.stderr.strip():
                print("  stderr:", r.stderr.strip()[:600])
    finally:
        sandbox.stop()
        proxy.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
