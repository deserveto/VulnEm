"""Top-level scan runner: builds the coordinator graph and drives it home.

One entry point, two shapes:
- solo: the Phase 1 single agent (hands-on tools, ``finish_scan``)
- graph (default): a root orchestrator that spawns specialists
- resume: rebuild a coordinator from a run directory's snapshot
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnem.agent.prompt import (
    build_initial_task,
    build_root_initial_task,
    build_root_prompt,
    build_system_prompt,
)
from vulnem.agent.tools import FINISH_TOOL
from vulnem.agents.coordinator import (
    TERMINAL_STATUSES,
    AgentRecord,
    AgentStatus,
    Budget,
    Coordinator,
)
from vulnem.agents.graph_tools import AGENT_FINISH_TOOL, GRAPH_TOOL_NAMES
from vulnem.agents.session import (
    HANDS_ON_SESSION_TOOLS,
    AgentSession,
    spawn_agent_task,
)
from vulnem.config import Settings
from vulnem.report.findings import Finding
from vulnem.sandbox import Sandbox
from vulnem.scope import Scope

logger = logging.getLogger(__name__)

ROOT_TOOLS = ({"think", "read_skill", FINISH_TOOL} | GRAPH_TOOL_NAMES) - {AGENT_FINISH_TOOL}
SOLO_TOOLS = set(HANDS_ON_SESSION_TOOLS) | {FINISH_TOOL}

CompletionFn = Callable[[list[dict[str, Any]], list[dict[str, Any]]], Any]


@dataclass(slots=True)
class ScanResult:
    finished: bool
    stop_reason: str  # finish_tool | max_turns | scan_budget | stalled | stopped | error
    summary: str
    findings: list[Finding] = field(default_factory=list)
    turns_used: int = 0
    total_tokens: int = 0
    transcript_path: Path | None = None
    run_dir: Path | None = None


def _restore_record(coordinator: Coordinator, data: dict[str, Any]) -> AgentRecord:
    """Rebuild an AgentRecord from a snapshot entry, preserving identity."""
    record = AgentRecord(
        agent_id=data["agent_id"],
        name=data["name"],
        role=data["role"],
        parent_id=data.get("parent_id"),
        objective=data.get("objective", ""),
        max_turns=int(data.get("max_turns", 30)),
        status=AgentStatus(data.get("status", "running")),
        turns_used=int(data.get("turns_used", 0)),
        total_tokens=int(data.get("total_tokens", 0)),
        completion_report=data.get("completion_report"),
        error=data.get("error"),
        stop_reason=data.get("stop_reason", ""),
    )
    coordinator.agents[record.agent_id] = record
    coordinator._by_name[record.name] = record.agent_id
    num = int(record.agent_id.lstrip("a")) if record.agent_id[1:].isdigit() else 0
    coordinator._counter = max(coordinator._counter, num)
    if record.terminal:
        record.done_event.set()
    return record


def _patch_dangling_tool_calls(messages: list[dict[str, Any]]) -> None:
    """After a crash/restore, append synthetic results for tool calls that
    never got one — providers reject dangling tool_call ids."""
    pending: dict[int, list[str]] = {}
    for i, msg in enumerate(messages):
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            pending[i] = [tc["id"] for tc in msg["tool_calls"]]
        elif msg.get("role") == "tool" and msg.get("tool_call_id"):
            for ids in pending.values():
                if msg["tool_call_id"] in ids:
                    ids.remove(msg["tool_call_id"])
    for _, ids in pending.items():
        for tc_id in ids:
            messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "content": "[system] The scan was interrupted before this tool "
                           "returned; its result is unknown. Re-assess the current "
                           "state (view_agent_graph if you are root) and continue.",
            })


async def run_scan(
    *,
    scope: Scope,
    settings: Settings,
    sandbox: Sandbox,
    run_dir: Path,
    solo: bool = False,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    completion_fn: CompletionFn | None = None,
    budget_turns: int | None = None,
    resume_state: dict[str, Any] | None = None,
    proxy: Any | None = None,
    creds: Any | None = None,
    focus: str | None = None,
) -> ScanResult:
    """Run one scan (solo or coordinated graph) to completion."""
    if resume_state is not None:
        budget = Budget.from_dict(resume_state.get("budget", {}))
    else:
        turns_cap = budget_turns if budget_turns is not None else settings.max_turns * (
            1 if solo else 4
        )
        budget = Budget(max_turns=turns_cap, max_tokens=settings.max_total_tokens)

    coordinator = Coordinator(
        run_dir=run_dir, max_agents=settings.max_agents, budget=budget, on_event=on_event
    )
    exec_semaphore = asyncio.Semaphore(settings.max_concurrent_exec)
    transcript = run_dir / "transcript.jsonl"

    # -- Phase 3 plumbing: proxy sidecar + authenticated session ----------------
    poll_task: asyncio.Task | None = None
    auth_cookies: list[dict[str, Any]] = []
    auth_storage: list[dict[str, str]] = []
    auth_origin = ""
    auth_bearer = False
    if proxy is not None:
        proxy.bind(coordinator, run_dir)
        poll_task = asyncio.create_task(proxy.poll_loop(), name="proxy-poller")
        coordinator.emit({
            "type": "proxy_started",
            "sidecar": proxy.name,
            "network": settings.docker_network or "default",
            "scope_hosts": list(scope.allowed_hosts),
        })
    if creds is not None:
        from vulnem.auth import AuthSession, stage_session

        auth = AuthSession(creds)
        result_auth = await asyncio.to_thread(
            auth.establish, sandbox=sandbox, proxy_url=getattr(sandbox, "proxy_url", None)
        )
        coordinator.emit({"type": "auth_established", **result_auth.describe(),
                          "login_url": creds.login_url})
        if result_auth.ok:
            auth_cookies = result_auth.cookies
            auth_storage = list(result_auth.storage)
            # Token-auth apps: also seed the SPA's localStorage if configured.
            storage_key = (creds.api or {}).get("token_storage_key")
            if result_auth.bearer and storage_key:
                auth_storage = [s for s in auth_storage if s.get("key") != storage_key]
                auth_storage.append({"key": str(storage_key), "value": result_auth.bearer})
            auth_origin = result_auth.origin
            auth_bearer = bool(result_auth.bearer)
            await asyncio.to_thread(stage_session, sandbox, result_auth)

    coordinator.emit({
        "type": "scan_start",
        "target": scope.target_url,
        "model": settings.model,
        "mode": "solo" if solo else "graph",
        "resumed": resume_state is not None,
        "budget_turns": budget.max_turns,
        "proxy": proxy is not None,
        "authenticated": bool(auth_cookies),
        "scope_mode": "diff" if focus else "full",
    })

    tasks: list[asyncio.Task] = []
    root_record: AgentRecord | None = None

    def make_session(record: AgentRecord, *, system_prompt: str, initial_task: str,
                     tool_names: set[str], finish_tool: str,
                     restored: list[dict[str, Any]] | None = None) -> AgentSession:
        return AgentSession(
            record=record,
            coordinator=coordinator,
            scope=scope,
            settings=settings,
            sandbox=sandbox,
            tool_names=tool_names,
            finish_tool=finish_tool,
            system_prompt=system_prompt,
            initial_task=initial_task,
            completion_fn=completion_fn,
            exec_semaphore=exec_semaphore,
            restored_messages=restored,
            proxy=proxy,
            auth_cookies=auth_cookies,
            auth_storage=auth_storage,
            auth_origin=auth_origin,
            auth_bearer=auth_bearer,
            run_dir=run_dir,
        )

    if resume_state is not None:
        # -- resume: rebuild every record, re-spawn the non-terminal ones ----
        for data in resume_state.get("agents", []):
            record = _restore_record(coordinator, data)
            if record.role == "root":
                root_record = record
            session_data = Coordinator.load_session(run_dir, record.agent_id)
            restored_findings = [Finding.model_validate(f)
                                 for f in session_data.get("findings", [])]
            if record.terminal:
                # not re-spawned: keep its findings so the final report keeps them
                record.restored_findings = restored_findings
                continue
            messages = session_data.get("messages", [])
            _patch_dangling_tool_calls(messages)
            messages.append({
                "role": "user",
                "content": (
                    "[system] The scan was interrupted and has been RESUMED. Time "
                    "has passed and the sandbox was reset (scratch files under /tmp "
                    "are gone; the target is unchanged). Continue your mission from "
                    "where the transcript leaves off."
                ),
            })
            if record.role == "root":
                tools, finish = ROOT_TOOLS, FINISH_TOOL
            elif record.role == "solo":
                tools, finish = SOLO_TOOLS, FINISH_TOOL
            else:
                tools, finish = set(HANDS_ON_SESSION_TOOLS) | {AGENT_FINISH_TOOL}, AGENT_FINISH_TOOL
            session = make_session(
                record, system_prompt="", initial_task="",
                tool_names=tools, finish_tool=finish, restored=messages,
            )
            session.ctx.findings = [Finding.model_validate(f)
                                    for f in session_data.get("findings", [])]
            record.task = spawn_agent_task(session)
            tasks.append(record.task)
        if root_record is None:
            root_record = coordinator.root
    elif solo:
        record = coordinator.register(
            name="solo", role="solo", parent_id=None,
            objective=f"Solo assessment of {scope.target_url}",
            max_turns=settings.max_turns,
        )
        session = make_session(
            record,
            system_prompt=build_system_prompt(scope, max_turns=settings.max_turns,
                                              authenticated=bool(auth_cookies)),
            initial_task=build_initial_task(scope, authenticated=bool(auth_cookies),
                                            focus=focus),
            tool_names=SOLO_TOOLS,
            finish_tool=FINISH_TOOL,
        )
        root_record = record
        record.task = spawn_agent_task(session)
        tasks.append(record.task)
    else:
        record = coordinator.register(
            name="root", role="root", parent_id=None,
            objective=f"Orchestrate assessment of {scope.target_url}",
            max_turns=settings.max_turns,
        )
        session = make_session(
            record,
            system_prompt=build_root_prompt(
                scope, max_turns=settings.max_turns, budget_turns=budget.max_turns
            ),
            initial_task=build_root_initial_task(scope, focus=focus),
            tool_names=ROOT_TOOLS,
            finish_tool=FINISH_TOOL,
        )
        root_record = record
        record.task = spawn_agent_task(session)
        tasks.append(record.task)

    await coordinator.snapshot_async()

    # -- drive to completion ------------------------------------------------
    stop_reason = "error"
    summary = ""
    finished = False
    try:
        if root_record is not None and root_record.task is not None:
            outcome = await root_record.task
            finished = outcome.finished
            stop_reason = outcome.stop_reason
            summary = outcome.summary
        else:
            stop_reason = "already_finished"
            summary = "Scan was already finished when resumed."
            finished = True
        # wait briefly for stragglers, then cancel anything still live
        live = [r for r in coordinator.agents.values() if not r.terminal]
        if live:
            await asyncio.wait(
                [r.task for r in live if r.task is not None],
                timeout=15,
            )
        for r in live:
            if not r.terminal:
                coordinator.set_status(r, AgentStatus.STOPPED, "scan ended")
            if r.task is not None and not r.task.done():
                r.task.cancel()
    except asyncio.CancelledError:
        # Operator interrupt: snapshot as-is WITHOUT marking agents terminal —
        # running/waiting agents are exactly what `vulnem resume` continues.
        stop_reason = "interrupted"
        summary = "Scan interrupted by operator (state snapshotted; `vulnem resume` can continue)."
        for r in coordinator.agents.values():
            if r.task is not None and not r.task.done():
                r.task.cancel()
        raise
    finally:
        await coordinator.snapshot_async()

    if poll_task is not None:
        poll_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await poll_task
    if proxy is not None:
        # Last drain so the transcript ends with every captured flow, then
        # freeze the full proxy log into the run dir as report evidence.
        await asyncio.to_thread(proxy.drain_final_events)
        await asyncio.to_thread(proxy.snapshot_evidence, run_dir)

    findings = coordinator.collect_findings()
    coordinator.emit({
        "type": "scan_end",
        "stop_reason": stop_reason,
        "turns_used": budget.turns_used,
        "total_tokens": budget.tokens_used,
        "findings": len(findings),
    })

    if not summary:
        summary = _synthesize_summary(coordinator, scope)
    return ScanResult(
        finished=finished,
        stop_reason=stop_reason,
        summary=summary,
        findings=findings,
        turns_used=budget.turns_used,
        total_tokens=budget.tokens_used,
        transcript_path=transcript,
        run_dir=run_dir,
    )


def _synthesize_summary(coordinator: Coordinator, scope: Scope) -> str:
    """When the root never finished cleanly, build the summary from the
    completion reports that did arrive."""
    lines = [f"Assessment of {scope.target_url} ended without a root summary "
             f"(stop reason recorded in state.json). Per-agent outcomes:"]
    for r in sorted(coordinator.agents.values(), key=lambda a: a.created_at):
        report = r.completion_report
        if report:
            lines.append(f"- {r.name} [{r.status.value}]: {report.get('summary', '')}")
        else:
            lines.append(f"- {r.name} [{r.status.value}]: {r.error or r.stop_reason or 'no report'}")
    return "\n".join(lines)


def load_resume_state(run_dir: Path) -> dict[str, Any]:
    """Load a snapshot for `vulnem resume`; raises with a clear message if
    the run cannot be resumed."""
    state = Coordinator.load_state(run_dir)
    agents = state.get("agents", [])
    if not agents:
        raise ValueError(f"snapshot in {run_dir} has no agents")
    live = [a for a in agents
            if AgentStatus(a.get("status", "running")) not in TERMINAL_STATUSES]
    if not live:
        raise ValueError("scan already finished — nothing to resume "
                         "(see report.md / findings.json)")
    config_path = run_dir / "config.json"
    if not config_path.is_file():
        raise ValueError(f"missing config.json in {run_dir}")
    return state


def read_run_config(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
