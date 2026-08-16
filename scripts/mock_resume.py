"""Interrupt + `vulnem resume` end-to-end test with a scripted fake LLM.

Runs the REAL stack — persistent lab (docker compose vulnem-lab, internal
labnet network), real sandbox container, mitmproxy sidecar with the
scope-guard addon, coordinator graph, snapshot/restore — with
litellm.completion replaced by a canned per-agent script. No LLM key needed.

Two phases, one process:

1. INTERRUPT — a scripted graph scan (root + fast-prober + slow-mapper) is
   cancelled mid-flight exactly like an operator Ctrl+C: the run_scan task
   is cancelled while root is parked in wait_for_agents and slow-mapper is
   blocked inside a long exec. The CancelledError path must snapshot
   state as-is (root waiting, slow running — never marked terminal).
2. RESUME — the real `cli._run_resume(run_dir)` continues the run: proxy
   sidecar re-provisioned (CA into the fresh sandbox), dangling tool calls
   repaired, agents restored, slow-mapper CONTINUES its mission (not
   salvaged), root wraps up via finish_scan, report exported.

Usage:  docker compose -p vulnem-lab -f lab/docker-compose.yml up -d
        .venv/Scripts/python scripts/mock_resume.py
Exit codes: 0 = resume verified, 2 = verification failed.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
import time
import types
import uuid
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

LAB_NETWORK = "vulnem-lab_labnet"
TARGET = "http://juice-shop:3000"

# Phase 1 scripts — consumed until the interrupt. slow-mapper's queue is
# deliberately long (5 x 30s sleeps) so it is guaranteed mid-exec when the
# cancel fires, and its phase-2 continuation is independent of how many
# sleeps phase 1 actually consumed.
ROOT_P1 = [
    ("Planning the decomposition.", "read_skill", {"name": "coordination/root_agent"}),
    ("", "create_agent", {"name": "fast-prober", "objective":
        "Probe {TARGET} reachability. Read `recon` first, file one mock "
        "finding, finish with agent_finish."}),
    ("", "create_agent", {"name": "slow-mapper", "objective":
        "Slow, thorough endpoint sweep of {TARGET}. Take your time."}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
]
FAST_P1 = [
    ("", "read_skill", {"name": "recon"}),
    ("Probing.", "exec_command",
     {"command": "curl -s -o /dev/null -w '%{http_code}' {TARGET}"}),
    ("Filing a finding pre-interrupt.", "report_finding", {
        "title": "Reachability marker finding (mock resume e2e)",
        "severity": "low", "cwe": "CWE-200",
        "url": "{TARGET}/",
        "description": "Filed before the interrupt; must survive the resume.",
        "evidence": "curl 200 from fast-prober before interruption.",
        "poc": "curl -s -o /dev/null -w '%{http_code}' {TARGET}",
        "remediation": "Ignore - plumbing test artifact.",
        "confidence": "high",
    }),
    ("Done before the interrupt.", "agent_finish", {"status": "completed",
        "summary": "Target reachable; mock finding filed."}),
]
SLOW_P1 = [
    ("", "read_skill", {"name": "recon"}),
    *[("Sweeping.", "exec_command",
       {"command": "sleep 30 && curl -s -o /dev/null -w '%{http_code}' {TARGET}"})
      for _ in range(5)],
]

# Phase 2 scripts — used only after the interrupt. Root re-parks (woken by
# slow-mapper's completion report), surveys, then finishes the scan.
ROOT_P2 = [
    ("", "wait_for_agents", {}),
    ("", "view_agent_graph", {}),
    ("Resumed scan complete.", "finish_scan", {"summary":
        "Resumed scan finished: slow-mapper continued its sweep after the "
        "interruption and completed properly; the pre-interrupt finding "
        "survived the snapshot/restore."}),
]
FAST_P2: list = []   # terminal in phase 1 — never re-spawned
SLOW_P2 = [
    ("Resumed — finishing the sweep.", "exec_command",
     {"command": "curl -s -o /dev/null -w '%{http_code}' {TARGET}"}),
    ("Sweep done after resume.", "agent_finish", {"status": "completed",
        "summary": "Endpoint sweep completed after resume; target healthy."}),
]


def _subst(obj, target: str):
    if isinstance(obj, str):
        return obj.replace("{TARGET}", target)
    if isinstance(obj, dict):
        return {k: _subst(v, target) for k, v in obj.items()}
    return obj


class ScriptedGraphLLM:
    """Routes scripted turns per agent; `phase` selects pre/post-interrupt
    queues (set to 2 once the interrupt landed, before the resume)."""

    def __init__(self) -> None:
        self.phase = 1
        self.queues: dict[tuple[int, str], list] = {}
        self._i = 0

    def _script(self, key: str) -> list:
        scripts = {
            1: {"root": ROOT_P1, "fast-prober": FAST_P1, "slow-mapper": SLOW_P1},
            2: {"root": ROOT_P2, "fast-prober": FAST_P2, "slow-mapper": SLOW_P2},
        }[self.phase]
        return scripts[key]

    def __call__(self, **kwargs):
        messages = kwargs.get("messages", [])
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        if "ROLE: ROOT ORCHESTRATOR" in system:
            key = "root"
        elif "ROLE: SPECIALIST (" in system:
            key = system.split("ROLE: SPECIALIST (", 1)[1].split(")", 1)[0]
        else:
            raise AssertionError("scripted LLM cannot route this session")
        queue = self.queues.setdefault((self.phase, key), list(self._script(key)))
        if not queue:
            raise AssertionError(f"phase-{self.phase} script for {key!r} exhausted")
        text, name, args = queue.pop(0)
        target = TARGET  # fixed lab URL; scripts carry {TARGET} placeholders
        self._i += 1
        if name is None:
            message = types.SimpleNamespace(content=text, tool_calls=None)
        else:
            tc = types.SimpleNamespace(
                id=f"call_{self._i}",
                function=types.SimpleNamespace(name=name,
                                                arguments=json.dumps(_subst(args, target))),
            )
            message = types.SimpleNamespace(content=text, tool_calls=[tc])
        usage = types.SimpleNamespace(prompt_tokens=100, completion_tokens=20)
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(message=message)], usage=usage
        )


def _ready_to_interrupt(events: list[dict]) -> bool:
    """Root parked on its 2nd wait AND slow-mapper blocked in a long exec
    AND fast-prober completed — cancel here for maximum resume surface."""
    root_parks = sum(1 for e in events if e.get("type") == "agent_status"
                     and e.get("agent") == "root" and e.get("to") == "waiting")
    fast_done = any(e.get("type") == "agent_status" and e.get("agent") == "fast-prober"
                    and e.get("to") == "completed" for e in events)
    slow_mid_exec = any(
        e.get("type") == "tool_call" and e.get("name") == "exec_command"
        and "sleep" in str((e.get("args") or {}).get("command", ""))
        and (e.get("agent_ctx") or {}).get("name") == "slow-mapper"
        for e in events)
    return root_parks >= 2 and fast_done and slow_mid_exec


async def _interrupted_scan(engine: ScriptedGraphLLM, settings, scope, run_dir: Path,
                            events: list[dict]) -> bool:
    """Phase 1: run the real scan until the interrupt point, then cancel the
    run_scan task — the same CancelledError path an operator Ctrl+C takes."""
    from vulnem.proxy.manager import ProxyManager
    from vulnem.sandbox import Sandbox
    from vulnem.scan import run_scan

    proxy = ProxyManager(scope=scope, network=LAB_NETWORK)
    proxy.start()
    sandbox = Sandbox(image=settings.sandbox_image, user=settings.sandbox_user,
                      network=LAB_NETWORK, proxy_url=proxy.sandbox_proxy_url)
    sandbox.start()
    try:
        task = asyncio.create_task(run_scan(
            scope=scope, settings=settings, sandbox=sandbox, run_dir=run_dir,
            on_event=events.append,
        ))
        deadline = time.time() + 300
        while time.time() < deadline and not _ready_to_interrupt(events):
            await asyncio.sleep(0.25)
        if time.time() >= deadline:
            print("  interrupt condition never reached (lab too slow?)")
            return False
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return True
    finally:
        sandbox.stop()
        proxy.stop()


def _verify_interrupted(run_dir: Path) -> list[str]:
    problems: list[str] = []
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    agents = {a["name"]: a for a in state["agents"]}
    # root: waiting or running (the parked wait's finally may flip it) —
    # what matters is NON-terminal so `vulnem resume` continues it
    if agents.get("root", {}).get("status") not in {"waiting", "running"}:
        problems.append(f"post-interrupt root status="
                        f"{agents.get('root', {}).get('status')!r}, want waiting/running")
    if agents.get("slow-mapper", {}).get("status") != "running":
        problems.append(f"post-interrupt slow-mapper status="
                        f"{agents.get('slow-mapper', {}).get('status')!r}, want running")
    if agents.get("fast-prober", {}).get("status") != "completed":
        problems.append(f"post-interrupt fast-prober status="
                        f"{agents.get('fast-prober', {}).get('status')!r}, want completed")
    if (run_dir / "findings.json").is_file():
        problems.append("findings.json written for an interrupted scan")
    if not (run_dir / "transcript.jsonl").is_file():
        problems.append("no transcript after interrupt")
    return problems


def _verify_resumed(run_dir: Path) -> list[str]:
    problems: list[str] = []
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    agents = {a["name"]: a for a in state["agents"]}
    for name in ("root", "slow-mapper", "fast-prober"):
        if agents.get(name, {}).get("status") != "completed":
            problems.append(f"post-resume {name} status="
                            f"{agents.get(name, {}).get('status')!r}, want completed")
    slow_report = (agents.get("slow-mapper", {}).get("completion_report") or {})
    if "after resume" not in (slow_report.get("summary") or ""):
        problems.append("slow-mapper did not file its post-resume completion report "
                        "(continued work lost?)")

    transcript = [json.loads(line) for line in
                  (run_dir / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    starts = [e for e in transcript if e.get("type") == "scan_start"]
    if len(starts) != 2 or not starts[1].get("resumed"):
        problems.append(f"scan_start events wrong: {len(starts)} starts, "
                        f"resumed={starts[1].get('resumed') if len(starts) > 1 else None}")
    ends = [e for e in transcript if e.get("type") == "scan_end"]
    if not ends or ends[-1].get("stop_reason") != "finish_tool":
        problems.append(f"scan_end wrong: {[e.get('stop_reason') for e in ends]}")
    # slow-mapper must CONTINUE after the resume (real tool work post-resume,
    # not an AUTO-SALVAGE sweep by root's finish_scan)
    if len(starts) == 2:
        resume_idx = transcript.index(starts[1])
        post = transcript[resume_idx:]
        if not any(e.get("type") == "tool_call" and e.get("name") == "exec_command"
                   and (e.get("agent_ctx") or {}).get("name") == "slow-mapper"
                   and "sleep" not in str((e.get("args") or {}).get("command", ""))
                   for e in post):
            problems.append("no post-resume exec by slow-mapper (continuation missing)")
    for e in transcript:
        if "AUTO-SALVAGED" in json.dumps(e):
            problems.append("an agent was salvaged on resume (should have continued)")
            break

    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    if not any("mock resume e2e" in f.get("title", "") for f in findings["findings"]):
        problems.append("pre-interrupt finding lost across the resume")

    for name in ("report.md", "findings.sarif", "report.pdf"):
        if not (run_dir / name).is_file():
            problems.append(f"{name} missing after resume")
    config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    if not config.get("proxy_effective"):
        problems.append("proxy_effective not true — proxy layer broken on resume")
    if not (run_dir / "proxy-flows.jsonl").is_file():
        problems.append("proxy-flows.jsonl evidence snapshot missing")

    sessions = list((run_dir / "sessions").glob("*.json")) if (run_dir / "sessions").is_dir() else []
    resumed_notes = 0
    for p in sessions:
        msgs = json.loads(p.read_text(encoding="utf-8")).get("messages", [])
        resumed_notes += sum(1 for m in msgs if m.get("role") == "user"
                             and "RESUMED" in str(m.get("content")))
    if resumed_notes < 2:
        problems.append(f"restored agents told about the resume {resumed_notes}x (want >= 2)")
    return problems


def main() -> int:
    from rich.console import Console

    console = Console()
    engine = ScriptedGraphLLM()
    started = time.time()

    import litellm

    litellm.completion = engine  # type: ignore[assignment]

    from vulnem import __version__
    from vulnem.cli import PROJECT_ROOT as ROOT
    from vulnem.cli import _resolve_paths
    from vulnem.config import Settings
    from vulnem.sandbox.docker import SandboxError
    from vulnem.scope import Scope

    settings = _resolve_paths(Settings.load(project_root=ROOT))
    scope = Scope.from_target(TARGET)

    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    run_dir = settings.runs_dir / f"{stamp}-juice-shop-r{uuid.uuid4().hex[:4]}"
    run_dir.mkdir(parents=True)
    events: list[dict] = []
    console.print(f"[bold]mock resume e2e[/bold] — lab target {TARGET}, run dir {run_dir.name}")

    console.print("[bold]Phase 1:[/bold] scripted scan interrupted mid-flight ...")
    try:
        interrupted = asyncio.run(_interrupted_scan(engine, settings, scope,
                                                    run_dir, events))
    except SandboxError as exc:
        console.print(f"[red]sandbox error:[/red] {exc} — is the lab up? "
                      "(docker compose -p vulnem-lab -f lab/docker-compose.yml up -d)")
        return 2
    if not interrupted:
        return 2
    problems = _verify_interrupted(run_dir)
    console.print(f"  interrupted: {len(events)} events; problems: {problems or 'none'}")
    if problems:
        for p in problems:
            console.print(f"  [red]FAIL[/red] {p}")
        return 2

    # Same run-config record `vulnem scan` writes — `_run_resume` reads it to
    # rebuild scope/network/proxy.
    (run_dir / "config.json").write_text(json.dumps({
        "target": scope.target_url,
        "model": settings.model,
        "network": LAB_NETWORK,
        "max_turns": settings.max_turns,
        "scan_budget_turns": None,
        "solo": False,
        "proxy": True,
        "creds": None,
        "ci": False,
        "fail_on": None,
        "scope_mode": "full",
        "source": None,
        "started_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "vulnem_version": __version__,
    }, indent=2), encoding="utf-8")

    console.print("[bold]Phase 2:[/bold] real `vulnem resume` (fresh sandbox + proxy) ...")
    engine.phase = 2
    from vulnem.cli import _run_resume

    settings2 = _resolve_paths(Settings.load(project_root=ROOT))
    rc = _run_resume(settings2, run_dir)

    problems = _verify_resumed(run_dir)
    console.print(f"\n[bold]mock resume verification[/bold] ({time.time() - started:.0f}s):")
    # The pre-interrupt finding must survive, so resume exits 1 (fail-on-findings).
    if problems or rc != 1:
        for p in problems or [f"resume exit code {rc} (want 1 = findings found)"]:
            console.print(f"  [red]FAIL[/red] {p}")
        return 2
    console.print("  [green]PASS[/green] interrupt snapshotted root=waiting, slow-mapper=running")
    console.print("  [green]PASS[/green] resume rebuilt graph, repaired dangling tool calls")
    console.print("  [green]PASS[/green] slow-mapper CONTINUED its mission (no salvage)")
    console.print("  [green]PASS[/green] pre-interrupt finding survived into the final report")
    console.print("  [green]PASS[/green] proxy re-provisioned (proxy_effective=true), flows snapshotted")
    console.print("  [green]PASS[/green] finish_scan ended the resumed run; SARIF + PDF exported; exit 1")
    console.print(f"  run dir: {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
