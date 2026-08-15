"""Graph + lifecycle tools: the multi-agent coordination surface.

Root-only tools (create_agent, view_agent_graph, send_message_to_agent,
wait_for_agents, stop_agent) and the lifecycle exits (finish_scan for
root/solo, agent_finish for specialists). Lifecycle tools are the ONLY way
an agent ends deliberately — plain text never ends a turn.

Schemas are merged into the shared SCHEMA_BY_NAME registry so sessions can
build per-role tool lists from names alone.
"""

from __future__ import annotations

import json
import re
from typing import Any

from vulnem.agent.prompt import build_specialist_prompt
from vulnem.agent.tools import FINISH_TOOL, SCHEMA_BY_NAME
from vulnem.agents.coordinator import AgentStatus, Message
from vulnem.agents.session import (
    HANDS_ON_SESSION_TOOLS,
    AgentSession,
    spawn_agent_task,
)
from vulnem.config import Settings

AGENT_FINISH_TOOL = "agent_finish"

_VALID_REPORT_STATUSES = {"completed", "failed", "blocked"}
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,30}$")


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


GRAPH_SCHEMAS: dict[str, dict[str, Any]] = {
    FINISH_TOOL: _fn(
        FINISH_TOOL,
        "End the ENTIRE scan (root/solo only). Call when all specialists have "
        "reported and you can write the final assessment: what was tested, what "
        "was found, coverage gaps, overall posture. This is the ONLY way to end "
        "the scan. Remaining live agents will be stopped.",
        {"summary": {"type": "string", "description": "Executive summary in markdown."}},
        ["summary"],
    ),
    AGENT_FINISH_TOOL: _fn(
        AGENT_FINISH_TOOL,
        "End YOUR agent run and file a structured completion report to your "
        "parent: status, summary, your filed findings (attached automatically), "
        "and recommendations. This is the ONLY way to finish your task. Report "
        "status 'failed' if you could not complete the objective, 'blocked' if "
        "something outside your control stopped you.",
        {
            "status": {"type": "string", "enum": ["completed", "failed", "blocked"]},
            "summary": {
                "type": "string",
                "description": "What you tested, what you found, what you could not test and why.",
            },
            "recommendations": {
                "type": "string",
                "description": "Follow-up work for the parent or the operator.",
            },
        },
        ["status", "summary"],
    ),
    "create_agent": _fn(
        "create_agent",
        "Spawn a specialist agent that runs CONCURRENTLY with you and your "
        "other agents, hands-on in the sandbox. Give each one a tight objective: "
        "one vulnerability class or surface, which skill to read first, what to "
        "prove, and to report findings with evidence. Objectives must include "
        "everything the specialist needs (they share your scope but not your "
        "context). 2-5 specialists in parallel is the sweet spot.",
        {
            "name": {
                "type": "string",
                "description": "Short unique slug, lowercase letters/digits/hyphens (e.g. 'sqli-search').",
            },
            "objective": {
                "type": "string",
                "description": "Full mission briefing for the specialist: target surface, "
                "vulnerability class, skill to read first, validation bar, budget hints.",
            },
            "max_turns": {
                "type": "integer",
                "description": "Optional turn budget for this specialist (default from settings).",
            },
        },
        ["name", "objective"],
    ),
    "view_agent_graph": _fn(
        "view_agent_graph",
        "Show the live agent graph: every agent's status, turns used vs cap, "
        "tokens, findings count, and completion-report status.",
        {},
        [],
    ),
    "send_message_to_agent": _fn(
        "send_message_to_agent",
        "Send a message to another agent. It is delivered on the agent's next "
        "turn; if the agent is parked waiting, the message revives it. Use for "
        "mid-run steering, scope corrections, or extra context.",
        {
            "agent": {"type": "string", "description": "Agent id or name."},
            "content": {"type": "string", "description": "Message body."},
            "priority": {"type": "string", "enum": ["normal", "high"]},
            "msg_type": {
                "type": "string",
                "enum": ["info", "instruction", "alert"],
                "description": "Defaults to 'instruction'.",
            },
        },
        ["agent", "content"],
    ),
    "wait_for_agents": _fn(
        "wait_for_agents",
        "Park until the given agents finish (reach a terminal status: "
        "completed/stopped/crashed/failed). Blocks ONCE — do not poll; when it "
        "returns you get each agent's outcome and completion report. Wakes "
        "early if a message arrives for you. With no ids, waits on all your "
        "live children.",
        {
            "agent_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Agent ids to wait on (default: all your live children).",
            },
            "timeout_s": {
                "type": "integer",
                "description": "Optional max seconds to park (default 1800).",
            },
        },
        [],
    ),
    "stop_agent": _fn(
        "stop_agent",
        "Force-stop a runaway or misbehaving agent (burning budget, stuck, or "
        "off-mission). It is marked stopped and its parent is notified.",
        {
            "agent": {"type": "string", "description": "Agent id or name."},
            "reason": {"type": "string", "description": "Why it is being stopped."},
        },
        ["agent", "reason"],
    ),
}

SCHEMA_BY_NAME.update(GRAPH_SCHEMAS)

GRAPH_TOOL_NAMES = set(GRAPH_SCHEMAS)


async def dispatch_graph_tool(name: str, args: dict[str, Any], sess: AgentSession) -> str | None:
    handler = _HANDLERS.get(name)
    if handler is None:
        return None
    try:
        return await handler(sess, args)
    except Exception as exc:  # tool failures go back to the model, never crash the loop
        import logging

        logging.getLogger(__name__).exception("graph tool %s failed", name)
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


# -- handlers -------------------------------------------------------------------


async def _tool_finish_scan(sess: AgentSession, args: dict[str, Any]) -> str:
    """End the whole scan: stop any still-live agents, record the summary."""
    coordinator = sess.coordinator
    summary = str(args.get("summary") or "(no summary provided)")
    stopped: list[str] = []
    for record in list(coordinator.agents.values()):
        if record is sess.record or record.terminal:
            continue
        record.stop_reason = record.stop_reason or "scan finished by root"
        coordinator.set_status(record, AgentStatus.STOPPED, "root finished scan")
        if record.task is not None and not record.task.done():
            record.task.cancel()
        stopped.append(record.name)
    sess.record.completion_report = {"status": "completed", "summary": summary}
    note = {"ok": True, "note": "scan finishing"}
    if stopped:
        note["stopped_agents"] = stopped
    return json.dumps(note)


async def _tool_agent_finish(sess: AgentSession, args: dict[str, Any]) -> str:
    """File a structured completion report into the parent's session, then end."""
    record = sess.record
    coordinator = sess.coordinator
    status = str(args.get("status") or "completed").lower()
    if status not in _VALID_REPORT_STATUSES:
        return json.dumps({"ok": False,
                           "error": f"status must be one of {sorted(_VALID_REPORT_STATUSES)}"})
    findings = [
        {"id": f.id, "title": f.title, "severity": f.severity, "url": f.url or "",
         "cwe": f.cwe or ""}
        for f in record.findings()
    ]
    report = {
        "agent": record.name,
        "status": status,
        "summary": str(args.get("summary") or "(no summary provided)"),
        "findings": findings,
        "recommendations": str(args.get("recommendations") or ""),
    }
    record.completion_report = report
    if record.parent_id:
        parent = coordinator.agents.get(record.parent_id)
        if parent is not None:
            body = (
                f"COMPLETION REPORT from specialist '{record.name}'\n"
                f"Status: {status}\n"
                f"Summary: {report['summary']}\n"
                f"Findings filed ({len(findings)}):\n"
                + ("\n".join(f"- [{f['severity']}] {f['title']} {f['url']}" for f in findings)
                   or "- (none)")
                + (f"\nRecommendations: {report['recommendations']}" if report["recommendations"] else "")
            )
            await coordinator.deliver(
                parent,
                Message(from_name=record.name, msg_type="completion_report",
                        priority="high", content=body),
            )
    return json.dumps({"ok": True, "note": "completion report filed to parent; finishing"})


async def _tool_create_agent(sess: AgentSession, args: dict[str, Any]) -> str:
    coordinator = sess.coordinator
    record = sess.record
    name = str(args.get("name") or "").strip().lower().replace(" ", "-").replace("_", "-")
    objective = str(args.get("objective") or "").strip()
    if not _NAME_RE.match(name):
        return json.dumps({"ok": False,
                           "error": "name must be 2-31 chars: lowercase letters, digits, hyphens"})
    if not objective:
        return json.dumps({"ok": False, "error": "objective is required"})
    settings: Settings = sess.settings
    max_turns = int(args.get("max_turns") or settings.child_max_turns)
    max_turns = max(3, min(max_turns, settings.max_turns * 2))

    try:
        child = coordinator.register(
            name=name, role="specialist", parent_id=record.agent_id,
            objective=objective, max_turns=max_turns,
        )
    except ValueError as exc:
        return json.dumps({"ok": False, "error": str(exc)})

    system_prompt = build_specialist_prompt(
        sess.scope, name=name, objective=objective,
        parent_name=record.name, max_turns=max_turns,
    )
    child_session = AgentSession(
        record=child,
        coordinator=coordinator,
        scope=sess.scope,
        settings=sess.settings,
        sandbox=sess.sandbox,
        tool_names=set(HANDS_ON_SESSION_TOOLS) | {AGENT_FINISH_TOOL},        finish_tool=AGENT_FINISH_TOOL,
        system_prompt=system_prompt,
        initial_task=objective,
        completion_fn=None if sess.completion_fn is None else sess.completion_fn,
        exec_semaphore=sess.shared_exec_semaphore(),
    )
    coordinator.emit({
        "type": "agent_created",
        "agent_id": child.agent_id,
        "agent": child.name,
        "parent_id": record.agent_id,
        "objective": objective[:300],
    })
    child.task = spawn_agent_task(child_session)
    return json.dumps({
        "ok": True,
        "agent_id": child.agent_id,
        "name": child.name,
        "note": "specialist started and running concurrently; use wait_for_agents "
                "to collect its report (no polling needed)",
    })


async def _tool_view_agent_graph(sess: AgentSession, _args: dict[str, Any]) -> str:
    return sess.coordinator.graph_view()


async def _tool_send_message(sess: AgentSession, args: dict[str, Any]) -> str:
    target = sess.coordinator.resolve(str(args.get("agent") or ""))
    if target is None:
        return json.dumps({"ok": False, "error": f"unknown agent {args.get('agent')!r}"})
    ok = await sess.coordinator.deliver(
        target,
        Message(
            from_name=sess.record.name,
            msg_type=str(args.get("msg_type") or "instruction"),
            priority=str(args.get("priority") or "normal"),
            content=str(args.get("content") or ""),
        ),
    )
    if not ok:
        return json.dumps({"ok": False,
                           "error": f"agent {target.name} is {target.status.value} (terminal); "
                                    "messages can only be delivered to live agents"})
    return json.dumps({"ok": True, "delivered_to": target.name})


async def _tool_wait_for_agents(sess: AgentSession, args: dict[str, Any]) -> str:
    coordinator = sess.coordinator
    ids = [str(i) for i in (args.get("agent_ids") or [])]
    if not ids:
        ids = [a.agent_id for a in coordinator.live_children_of(sess.record.agent_id)]
    if not ids:
        return json.dumps({"ok": True, "woken_by": "all_done", "agents": [],
                           "note": "no live agents matched; nothing to wait for"})
    unknown = [i for i in ids if i not in coordinator.agents]
    if unknown:
        return json.dumps({"ok": False, "error": f"unknown agent ids: {unknown}"})
    timeout_s = min(float(args.get("timeout_s") or 1800), 3600)
    result = await coordinator.wait_for(sess.record, ids, timeout_s=timeout_s)
    return json.dumps(result, ensure_ascii=False, default=str)


async def _tool_stop_agent(sess: AgentSession, args: dict[str, Any]) -> str:
    target = sess.coordinator.resolve(str(args.get("agent") or ""))
    if target is None:
        return json.dumps({"ok": False, "error": f"unknown agent {args.get('agent')!r}"})
    if target is sess.record:
        return json.dumps({"ok": False, "error": "cannot stop yourself; use your finish tool"})
    reason = str(args.get("reason") or "stopped by parent")
    msg = await sess.coordinator.stop_agent(target, reason)
    return json.dumps({"ok": True, "note": msg})


_HANDLERS = {
    FINISH_TOOL: _tool_finish_scan,
    AGENT_FINISH_TOOL: _tool_agent_finish,
    "create_agent": _tool_create_agent,
    "view_agent_graph": _tool_view_agent_graph,
    "send_message_to_agent": _tool_send_message,
    "wait_for_agents": _tool_wait_for_agents,
    "stop_agent": _tool_stop_agent,
}
