"""Multi-agent end-to-end plumbing test with a scripted fake LLM.

Runs the FULL stack — demo lab (Juice Shop on an internal network), real
sandbox container (with Playwright Chromium), mitmproxy sidecar with the
scope-guard addon, coordinator graph, agent sessions, graph tools, dedupe,
report writing — with litellm.completion replaced by a canned per-agent
script. Proves everything except the paid model call works, WITHOUT an LLM
API key.

The scripted root spawns FOUR specialists in parallel: recon, sqli-search,
access-control, and xss-browser. The browser specialist drives the REAL
headless Chromium through the browser tools and inspects the REAL proxy log
with the proxy tools, so the Phase 3 plumbing (daemon bring-up, per-agent
contexts, screenshot artifacts, flow capture via the sidecar) is exercised
end to end. Two agents deliberately report the same endpoint+class finding
so cross-agent dedupe must collapse them in the final report.

Usage:  .venv/Scripts/python scripts/mock_e2e.py
Exit codes: 0 = plumbing verified, 2 = verification failed.
"""

from __future__ import annotations

import json
import re
import sys
import time
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# (assistant_text, tool_name, tool_args) — {TARGET} is replaced with the
# real lab URL scraped from the conversation on each call.
ROOT_SCRIPT = [
    ("Planning the decomposition.", "read_skill", {"name": "coordination/root_agent"}),
    ("", "create_agent", {"name": "recon-mapper", "objective":
        "Map the attack surface of {TARGET}: fingerprint, endpoints, auth "
        "surface. Read `recon` first. Report a summary finding only if you "
        "find something concrete; finish with agent_finish."}),
    ("", "create_agent", {"name": "sqli-search", "objective":
        "Test SQL injection on the product search API of {TARGET} "
        "(/rest/products/search?q=). Read `sql_injection` first. Validate "
        "before reporting; always set the url field. Finish with "
        "agent_finish."}),
    ("", "create_agent", {"name": "access-probe", "objective":
        "Test broken access control on {TARGET} admin/API routes. Read "
        "`broken_access_control` first. Finish with agent_finish."}),
    ("", "create_agent", {"name": "xss-browser", "objective":
        "Exercise the browser tooling against {TARGET}: read "
        "`browser_testing`, navigate the home page, read it back, screenshot "
        "it, then inspect and replay a captured request via the proxy tools. "
        "File one mock finding citing the screenshot artifact. Finish with "
        "agent_finish."}),
    # Completion-report messages wake the root early — each wait returns on
    # one wake, so keep waiting until every specialist is terminal (the
    # scripted stand-in for a real root reacting to wait results).
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "view_agent_graph", {}),
    ("Scan complete.", "finish_scan", {"summary":
        "Mock E2E multi-agent scan: four specialists ran in parallel "
        "(including a browser-driven one); overlapping findings were merged; "
        "browser + proxy plumbing verified end to end."}),
]

RECON_SCRIPT = [
    ("", "read_skill", {"name": "recon"}),
    ("", "exec_command", {"command": "curl -s -o /dev/null -w '%{http_code}' {TARGET}"}),
    ("Recon done.", "agent_finish", {"status": "completed",
        "summary": "Juice Shop reachable; standard endpoints present."}),
]

SQLI_SCRIPT = [
    ("", "read_skill", {"name": "sql_injection"}),
    ("Probing search.", "exec_command",
     {"command": "curl -s '{TARGET}/rest/products/search?q=orange' | head -c 300"}),
    ("Filing the finding.", "report_finding", {
        "title": "SQL injection in product search (mock e2e)",
        "severity": "high",
        "cwe": "CWE-89",
        "url": "{TARGET}/rest/products/search?q=orange",
        "description": "Mock finding produced by scripts/mock_e2e.py to verify "
                       "the multi-agent report pipeline end to end.",
        "evidence": "curl output captured by scripted agent sqli-search.",
        "poc": "curl -s '{TARGET}/rest/products/search?q=orange'",
        "remediation": "Ignore - plumbing test artifact.",
        "confidence": "high",
    }),
    ("Done.", "agent_finish", {"status": "completed",
        "summary": "Search API exercised; mock finding filed."}),
]

ACCESS_SCRIPT = [
    ("", "read_skill", {"name": "broken_access_control"}),
    ("", "exec_command",
     {"command": "curl -s -o /dev/null -w '%{http_code}' {TARGET}/ftp"}),
    # Overlaps sqli-search: same endpoint + class -> must dedupe/merge.
    ("Filing overlapping finding.", "report_finding", {
        "title": "Injection in product search API (overlap)",
        "severity": "high",
        "cwe": "CWE-89",
        "url": "{TARGET}/rest/products/search?q=x",
        "description": "Deliberate duplicate from another agent to verify "
                       "cross-agent dedupe in the report.",
        "evidence": "overlap evidence from access-probe.",
        "poc": "curl -s '{TARGET}/rest/products/search?q=x'",
        "remediation": "Ignore - plumbing test artifact.",
        "confidence": "medium",
    }),
    ("Done.", "agent_finish", {"status": "completed",
        "summary": "FTP route checked; overlapping finding filed for dedupe."}),
]

# Drives the real Chromium daemon + real proxy sidecar. Flow id 1 is the
# first proxied request (recon's GET /), guaranteed to exist by ordering.
BROWSER_SCRIPT = [
    ("", "read_skill", {"name": "browser_testing"}),
    ("Loading the SPA in headless Chromium.", "browser_navigate", {"url": "{TARGET}"}),
    ("Reading the rendered DOM back.", "browser_read_page", {}),
    ("Capturing visual evidence.", "browser_screenshot", {"name": "mock-e2e-home"}),
    ("Inspecting the proxy log.", "list_requests", {"q": "juice-shop", "limit": 10}),
    ("Viewing the first captured exchange.", "view_request", {"id": 1}),
    ("Replaying it through the proxy.", "repeat_request", {"id": 1}),
    ("Mapping everything the proxy saw.", "view_sitemap", {}),
    ("Filing the mock browser finding.", "report_finding", {
        "title": "Browser-rendered reflected marker on home page (mock e2e)",
        "severity": "low",
        "cwe": "CWE-79",
        "url": "{TARGET}/",
        "description": "Mock finding produced by the browser specialist to "
                       "verify Phase 3 browser + proxy plumbing end to end.",
        "evidence": "browser_read_page output of {TARGET} plus screenshot "
                    "artifact artifacts/xss-browser/ referenced in the "
                    "transcript; proxy flow log in proxy-flows.jsonl.",
        "poc": "browser_navigate {TARGET} then browser_read_page",
        "remediation": "Ignore - plumbing test artifact.",
        "confidence": "high",
    }),
    ("Done.", "agent_finish", {"status": "completed",
        "summary": "Browser navigated, screenshotted, proxy log inspected "
                   "and one request replayed through the sidecar."}),
]

SCRIPTS_BY_AGENT = {
    "root": ROOT_SCRIPT,
    "recon-mapper": RECON_SCRIPT,
    "sqli-search": SQLI_SCRIPT,
    "access-probe": ACCESS_SCRIPT,
    "xss-browser": BROWSER_SCRIPT,
}


def _make_response(idx: int, text: str, name: str, args: str):
    if name is None:
        message = types.SimpleNamespace(content=text, tool_calls=None)
    else:
        tc = types.SimpleNamespace(
            id=f"call_{idx}", function=types.SimpleNamespace(name=name, arguments=args)
        )
        message = types.SimpleNamespace(content=text, tool_calls=[tc])
    usage = types.SimpleNamespace(prompt_tokens=100, completion_tokens=20)
    return types.SimpleNamespace(
        choices=[types.SimpleNamespace(message=message)], usage=usage
    )


def _substitute(obj, target: str):
    if isinstance(obj, str):
        return obj.replace("{TARGET}", target)
    if isinstance(obj, dict):
        return {k: _substitute(v, target) for k, v in obj.items()}
    return obj


class ScriptedGraphLLM:
    """Routes scripted turns per agent via the system-prompt role markers."""

    def __init__(self) -> None:
        self.scripts: dict[str, list] = {}
        self._i = 0

    def __call__(self, **kwargs):
        messages = kwargs.get("messages", [])
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        if "ROLE: ROOT ORCHESTRATOR" in system:
            key = "root"
        elif "ROLE: SPECIALIST (" in system:
            key = system.split("ROLE: SPECIALIST (", 1)[1].split(")", 1)[0]
        elif "ROLE: SOLO" in system:
            key = "solo"
        else:
            raise AssertionError("scripted LLM cannot route this session")
        if key not in self.scripts:
            self.scripts[key] = list(SCRIPTS_BY_AGENT[key])
        queue = self.scripts[key]
        # The system prompt's scope block carries the authoritative target
        # URL (skill text and examples can contain look-alike URLs).
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        m = re.search(r"Target:\s*(http://\S+)", system)
        target = m.group(1).rstrip(".,'\")") if m else ""
        if not queue:
            raise AssertionError(f"script for {key!r} exhausted before finish")
        text, name, args = queue.pop(0)
        self._i += 1
        return _make_response(self._i, text, name,
                              json.dumps(_substitute(args, target)))


def _verify(run_dir: Path) -> list[str]:
    """Assert the multi-agent plumbing produced what Phase 2 + 3 promise."""
    problems: list[str] = []
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    agents = {a["name"]: a for a in state["agents"]}
    expected = {"root", "recon-mapper", "sqli-search", "access-probe", "xss-browser"}
    if set(agents) != expected:
        problems.append(f"agents in snapshot: {sorted(agents)} != {sorted(expected)}")
    for name in expected - {"root"}:
        if agents.get(name, {}).get("status") != "completed":
            problems.append(f"{name} status={agents.get(name, {}).get('status')!r}, want completed")
        if not agents.get(name, {}).get("completion_report"):
            problems.append(f"{name} filed no completion report")
    if agents.get("root", {}).get("status") != "completed":
        problems.append(f"root status={agents.get('root', {}).get('status')!r}, want completed")

    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))["findings"]
    sqli = [f for f in findings if f.get("cwe") == "CWE-89"]
    if len(sqli) != 1:
        problems.append(f"CWE-89 findings after dedupe: {len(sqli)} (want 1 merged)")
    elif "access-probe" not in (sqli[0].get("reported_by") or ""):
        problems.append(f"merged finding missing attribution: {sqli[0].get('reported_by')!r}")
    if not any(f.get("severity") == "high" for f in findings):
        problems.append("no high-severity finding in report")

    transcript = [
        json.loads(line)
        for line in (run_dir / "transcript.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    kinds = {e["type"] for e in transcript}
    for want in ("agent_created", "agent_status", "message_delivered", "tool_call"):
        if want not in kinds:
            problems.append(f"transcript missing {want} events")

    # -- Phase 3: browser + proxy plumbing --------------------------------
    for want_tool in ("browser_navigate", "browser_read_page", "browser_screenshot",
                      "list_requests", "view_request", "repeat_request", "view_sitemap"):
        calls = [e for e in transcript if e["type"] == "tool_call" and e.get("name") == want_tool]
        if not calls:
            problems.append(f"no {want_tool} call in transcript")
        elif calls[0].get("agent_ctx", {}).get("name") != "xss-browser":
            problems.append(f"{want_tool} not attributed to xss-browser")

    browser_results = [e for e in transcript if e["type"] == "tool_result"
                       and e.get("name") == "browser_navigate"]
    if not browser_results or '"ok": true' not in (browser_results[0].get("result") or ""):
        problems.append("browser_navigate did not succeed against the real target")

    shots = [e for e in transcript if e["type"] == "screenshot"]
    if not shots:
        problems.append("no screenshot evidence event in transcript")
    else:
        artifact = run_dir / shots[0].get("artifact", "")
        if not artifact.is_file() or artifact.stat().st_size < 1000:
            problems.append(f"screenshot artifact missing/empty: {shots[0].get('artifact')}")

    if "proxy_started" not in kinds:
        problems.append("no proxy_started event (sidecar lifecycle not wired)")
    flows = [e for e in transcript if e["type"] == "proxy_flow"]
    if len(flows) < 3:
        problems.append(f"only {len(flows)} proxy_flow events (want >= 3 captured exchanges)")
    if not any("/rest/products/search" in (e.get("path") or "") for e in flows):
        problems.append("proxy log missing the search-API exchange (flow capture gap)")
    repeat_results = [e for e in transcript if e["type"] == "tool_result"
                      and e.get("name") == "repeat_request"]
    if not repeat_results or '"ok": true' not in (repeat_results[0].get("result") or ""):
        problems.append("repeat_request did not replay through the proxy")
    evidence_log = run_dir / "proxy-flows.jsonl"
    if not evidence_log.is_file() or len(evidence_log.read_text(encoding="utf-8").splitlines()) < 3:
        problems.append("proxy-flows.jsonl evidence snapshot missing or thin")

    attributed = {e["agent_ctx"]["name"] for e in transcript if e["type"] == "tool_call"
                  and "agent_ctx" in e}
    if not {"root", "sqli-search"} <= attributed:
        problems.append(f"tool_call attribution incomplete: {sorted(attributed)}")
    # root must have parked exactly once while children ran
    waits = [e for e in transcript if e["type"] == "agent_status" and e.get("to") == "waiting"]
    if not waits:
        problems.append("root never entered waiting (wait_for_agents did not park)")
    return problems


def main() -> int:
    from rich.console import Console

    console = Console()
    script = ScriptedGraphLLM()
    started = time.time()

    import litellm

    litellm.completion = script  # type: ignore[assignment]

    from vulnem.cli import PROJECT_ROOT as ROOT
    from vulnem.cli import _resolve_paths, _run_demo
    from vulnem.config import Settings

    settings = _resolve_paths(Settings.load(project_root=ROOT))
    settings.yes = True
    rc = _run_demo(settings)

    run_dirs = sorted(
        (ROOT / "runs").glob("*juice-shop*"), key=lambda p: p.stat().st_mtime
    )
    if not run_dirs:
        console.print("[red]no run directory produced[/red]")
        return 2
    problems = _verify(run_dirs[-1])
    console.print(f"\n[bold]mock e2e verification[/bold] ({time.time() - started:.0f}s):")
    if problems or rc not in (0, 1):  # rc=1 means findings found (expected)
        for p in problems or [f"demo exit code {rc}"]:
            console.print(f"  [red]FAIL[/red] {p}")
        return 2
    console.print("  [green]PASS[/green] root spawned 4 specialists in parallel (incl. browser-driven)")
    console.print("  [green]PASS[/green] all specialists completed + filed reports")
    console.print("  [green]PASS[/green] overlapping findings deduped with merged attribution")
    console.print("  [green]PASS[/green] transcript carries per-agent attribution")
    console.print("  [green]PASS[/green] real Chromium driven via browser tools; screenshot artifact persisted")
    console.print("  [green]PASS[/green] proxy sidecar captured flows, enabled replay, snapshot saved")
    console.print(f"  run dir: {run_dirs[-1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
