"""Multi-agent end-to-end plumbing test with a scripted fake LLM.

Runs the FULL stack — demo lab (Juice Shop on an internal network), real
sandbox container, coordinator graph, agent sessions, graph tools, dedupe,
report writing — with litellm.completion replaced by a canned per-agent
script. Proves everything except the paid model call works.

The scripted root spawns THREE specialists in parallel (the Phase 2 demo
shape): recon, sqli-search, and access-control. Two of them deliberately
report the same endpoint+class finding so cross-agent dedupe must collapse
them in the final report.

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
    # A completion-report message can wake the root early — wait again so
    # every specialist is terminal before the graph view + finish.
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "view_agent_graph", {}),
    ("Scan complete.", "finish_scan", {"summary":
        "Mock E2E multi-agent scan: three specialists ran in parallel; "
        "overlapping findings were merged; plumbing verified end to end."}),
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
     {"command": "curl -s {TARGET}/rest/products/search?q=orange' | head -c 300"}),
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

SCRIPTS_BY_AGENT = {
    "root": ROOT_SCRIPT,
    "recon-mapper": RECON_SCRIPT,
    "sqli-search": SQLI_SCRIPT,
    "access-probe": ACCESS_SCRIPT,
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
    """Assert the multi-agent plumbing produced what Phase 2 promises."""
    problems: list[str] = []
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    agents = {a["name"]: a for a in state["agents"]}
    expected = {"root", "recon-mapper", "sqli-search", "access-probe"}
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
    console.print("  [green]PASS[/green] root spawned 3 specialists in parallel")
    console.print("  [green]PASS[/green] all specialists completed + filed reports")
    console.print("  [green]PASS[/green] overlapping findings deduped with merged attribution")
    console.print("  [green]PASS[/green] transcript carries per-agent attribution")
    console.print(f"  run dir: {run_dirs[-1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
