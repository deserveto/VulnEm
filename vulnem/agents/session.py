"""Per-agent session state and the async agent loop.

Extracted from Phase 1's single-agent loop so many agents can run
concurrently on one sandbox: each agent is an asyncio task, LLM calls and
sandbox execs run in worker threads, graph tools run on the event loop.

Session messages are kept as plain JSON dicts (never provider objects) so
snapshots, restore, and the future UI always have a stable shape.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from vulnem.agent.tools import (
    HANDS_ON_TOOL_NAMES,
    SCHEMA_BY_NAME,
    ToolContext,
    dispatch_tool,
)
from vulnem.agents.coordinator import AgentStatus, Coordinator, Message
from vulnem.config import Settings
from vulnem.scope import Scope

logger = logging.getLogger(__name__)

_COMPLETION_TIMEOUT_S = 300
_MAX_PROVIDER_RETRIES = 3
_MAX_TEXT_ONLY_TURNS = 3
# Turns an agent may still use to call its finish tool after the scan-wide
# budget is exhausted; then it is force-stopped.
_WRAPUP_GRACE_TURNS = 2

# The Phase 1 hands-on toolset shared by solo agents and specialists
# (browser_* + proxy_* joined in Phase 3 — all sync handlers).
HANDS_ON_SESSION_TOOLS = sorted(HANDS_ON_TOOL_NAMES)

CompletionFn = Callable[[list[dict[str, Any]], list[dict[str, Any]]], Any]


@dataclass(slots=True)
class AgentOutcome:
    stop_reason: str  # finish_tool | max_turns | scan_budget | stalled | stopped | error
    summary: str
    finished: bool


def _assistant_to_dict(message: Any) -> dict[str, Any]:
    """Normalize a provider assistant message into a plain JSON-able dict."""
    tool_calls = getattr(message, "tool_calls", None) or []
    return {
        "role": "assistant",
        "content": getattr(message, "content", None),
        "tool_calls": [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in tool_calls
        ] or None,
    }


class AgentSession:
    """One addressable agent: identity, LLM session, tools, budgets."""

    def __init__(
        self,
        *,
        record,
        coordinator: Coordinator,
        scope: Scope,
        settings: Settings,
        sandbox,
        tool_names: set[str],
        finish_tool: str,
        system_prompt: str,
        initial_task: str,
        completion_fn: CompletionFn | None = None,
        exec_semaphore: asyncio.Semaphore | None = None,
        restored_messages: list[dict[str, Any]] | None = None,
        proxy: Any | None = None,
        auth_cookies: list[dict[str, Any]] | None = None,
        auth_storage: list[dict[str, str]] | None = None,
        auth_origin: str = "",
        auth_bearer: bool = False,
        run_dir: Any | None = None,
    ) -> None:
        self.record = record
        self.coordinator = coordinator
        self.scope = scope
        self.settings = settings
        self.sandbox = sandbox
        self.tool_names = set(tool_names)
        self.finish_tool = finish_tool
        self.completion_fn = completion_fn
        self._exec_semaphore = exec_semaphore or asyncio.Semaphore(4)
        self.ctx = ToolContext(
            settings=settings, sandbox=sandbox, scope_host=scope.host,
            agent_name=record.name,
            allowed_hosts=scope.allowed_hosts,
            proxy=proxy,
            sandbox_proxy_url=getattr(proxy, "sandbox_proxy_url", None),
            auth_cookies=list(auth_cookies or []),
            auth_storage=list(auth_storage or []),
            auth_origin=auth_origin,
            auth_bearer=auth_bearer,
            run_dir=run_dir,
            emit_event=self.emit,
        )
        self.messages: list[dict[str, Any]] = restored_messages if restored_messages is not None else [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_task},
        ]
        record.session = self

    # -- wiring ---------------------------------------------------------------

    def tool_schemas(self) -> list[dict[str, Any]]:
        return [SCHEMA_BY_NAME[name] for name in sorted(self.tool_names)
                if name in SCHEMA_BY_NAME]

    def shared_exec_semaphore(self) -> asyncio.Semaphore:
        """The sandbox exec cap, shared across every agent in the graph."""
        return self._exec_semaphore

    def emit(self, event: dict[str, Any]) -> None:
        agent = {"id": self.record.agent_id, "name": self.record.name,
                 "role": self.record.role}
        if self.record.parent_id:
            agent["parent_id"] = self.record.parent_id
        self.coordinator.emit({**event, "agent_ctx": agent})

    def _completion_sync(self):
        """One LLM call with retries; runs inside a worker thread."""
        import litellm

        last_exc: Exception | None = None
        for attempt in range(_MAX_PROVIDER_RETRIES):
            try:
                if self.completion_fn is not None:
                    return self.completion_fn(self.messages, self.tool_schemas())
                return litellm.completion(
                    model=self.settings.model,
                    messages=self.messages,  # type: ignore[arg-type]
                    tools=self.tool_schemas(),
                    timeout=_COMPLETION_TIMEOUT_S,
                    num_retries=2,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_exc = exc
                logger.warning("completion attempt %d failed for %s: %s",
                               attempt + 1, self.record.name, exc)
                time.sleep(2**attempt)
        raise RuntimeError(
            f"LLM call failed after {_MAX_PROVIDER_RETRIES} attempts"
        ) from last_exc

    async def dispatch(self, name: str, args: dict[str, Any]) -> str:
        """Run one tool call. Graph tools await on the loop; hands-on tools
        (blocking exec) run in a worker thread under a concurrency cap."""
        from vulnem.agents.graph_tools import dispatch_graph_tool

        if name not in self.tool_names:
            return json.dumps({"ok": False, "error": f"tool {name!r} is not available to you"})
        if name in HANDS_ON_TOOL_NAMES:
            async with self._exec_semaphore:
                return await asyncio.to_thread(dispatch_tool, name, args, self.ctx)
        result = await dispatch_graph_tool(name, args, self)
        if result is None:
            return json.dumps({"ok": False, "error": f"unknown tool {name!r}"})
        return result

    def inject_user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def drain_messages_into_session(self) -> None:
        for msg in self.coordinator.drain_mailbox(self.record):
            self.emit({"type": "message_delivered", "from": msg.from_name,
                       "msg_type": msg.msg_type, "preview": msg.content[:120]})
            self.inject_user(msg.render())


async def run_agent(session: AgentSession) -> AgentOutcome:
    """Drive one agent until its lifecycle tool, a cap, or a stop."""
    record = session.record
    coordinator = session.coordinator
    stop_reason = "error"
    summary = ""
    finished = False
    text_only_streak = 0
    wrapup_turns_left = _WRAPUP_GRACE_TURNS

    session.emit({"type": "agent_start", "objective": record.objective[:300]})

    try:
        while True:
            # -- caps (checked before every turn) -----------------------------
            if record.turns_used >= record.max_turns:
                stop_reason = "max_turns"
                summary = f"Agent {record.name} hit its per-agent turn cap."
                break
            if coordinator.budget.exhausted and wrapup_turns_left <= 0:
                stop_reason = "scan_budget"
                summary = f"Agent {record.name} force-stopped: scan-wide budget exhausted."
                break

            session.drain_messages_into_session()

            record.turns_used += 1
            within_budget = coordinator.budget.charge_turn()
            if not within_budget and wrapup_turns_left == _WRAPUP_GRACE_TURNS:
                session.inject_user(
                    "[system] SCAN-WIDE BUDGET EXHAUSTED. Call your finish tool "
                    f"(`{session.finish_tool}`) NOW with what you have."
                )
            if not within_budget:
                wrapup_turns_left -= 1

            response = await asyncio.to_thread(session._completion_sync)

            usage = getattr(response, "usage", None)
            if usage is not None:
                tokens = int(getattr(usage, "prompt_tokens", 0) or 0) + int(
                    getattr(usage, "completion_tokens", 0) or 0
                )
                record.total_tokens += tokens
                coordinator.budget.charge_tokens(tokens)

            message = response.choices[0].message
            tool_calls = getattr(message, "tool_calls", None) or []
            text = (getattr(message, "content", None) or "").strip()
            if text:
                session.emit({"type": "assistant_text", "turn": record.turns_used,
                              "text": text})

            if not tool_calls:
                text_only_streak += 1
                if text_only_streak >= _MAX_TEXT_ONLY_TURNS:
                    stop_reason = "stalled"
                    summary = (f"Agent {record.name} produced several consecutive "
                               "turns without calling any tool.")
                    break
                session.inject_user(
                    "[system] Your last turns had no tool call. Every turn must "
                    f"end with exactly one tool call. Call `{session.finish_tool}` "
                    "with a summary if you are done."
                )
                session.emit({"type": "nudge", "turn": record.turns_used,
                              "streak": text_only_streak})
                continue

            text_only_streak = 0
            session.messages.append(_assistant_to_dict(message))

            for tc in tool_calls:
                name = tc.function.name
                raw_args = tc.function.arguments
                try:
                    if isinstance(raw_args, dict):
                        args = raw_args
                    elif isinstance(raw_args, str) and raw_args.strip():
                        args = json.loads(raw_args)
                    else:
                        args = {}
                    if not isinstance(args, dict):
                        args = {"input": args}
                except json.JSONDecodeError as exc:
                    args = {}
                    result = json.dumps(
                        {"ok": False, "error": f"invalid tool arguments JSON: {exc}"}
                    )
                else:
                    session.emit({"type": "tool_call", "turn": record.turns_used,
                                  "name": name, "args": args})
                    result = await session.dispatch(name, args)
                session.emit({"type": "tool_result", "turn": record.turns_used,
                              "name": name, "result": result[:4000]})
                session.messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })
                if name == session.finish_tool:
                    # A rejected lifecycle call (bad args) returns ok:false —
                    # the agent must continue, not finish.
                    try:
                        accepted = json.loads(result).get("ok", True) is not False
                    except (ValueError, AttributeError):
                        accepted = True
                    if accepted:
                        stop_reason = "finish_tool"
                        finished = True
                        summary = str(args.get("summary") or summary)
                        break
            if finished:
                break

            await coordinator.snapshot_async()
    except asyncio.CancelledError:
        stop_reason = "stopped"
        summary = summary or f"Agent {record.name} was stopped."
    except Exception as exc:
        logger.exception("agent %s failed", record.name)
        stop_reason = "error"
        summary = f"Agent {record.name} aborted by error: {exc}"
        record.error = f"{type(exc).__name__}: {exc}"

    await finalize_agent(session, AgentOutcome(stop_reason=stop_reason, summary=summary,
                                               finished=finished))
    return AgentOutcome(stop_reason=stop_reason, summary=summary, finished=finished)


async def finalize_agent(session: AgentSession, outcome: AgentOutcome) -> None:
    """Map an outcome onto the final registry status + notify the parent.

    Order matters: everything (parent alert, final snapshot) happens BEFORE
    set_status flips the record terminal — that is what wakes parked waiters,
    and they must observe a fully persisted agent.
    """
    record = session.record
    coordinator = session.coordinator
    if record.terminal:
        return  # stop_agent already decided the outcome

    if outcome.finished:
        report = record.completion_report or {}
        status = AgentStatus.FAILED if report.get("status") == "failed" else AgentStatus.COMPLETED
    elif outcome.stop_reason in {"max_turns", "stalled", "error", "token_budget"}:
        status = AgentStatus.FAILED
        record.error = record.error or outcome.summary
    else:  # stopped | scan_budget | interrupted
        status = AgentStatus.STOPPED

    record.stop_reason = record.stop_reason or outcome.stop_reason
    session.emit({
        "type": "agent_end",
        "stop_reason": outcome.stop_reason,
        "turns_used": record.turns_used,
        "total_tokens": record.total_tokens,
        "findings": len(record.findings()),
    })
    if status in {AgentStatus.FAILED, AgentStatus.CRASHED} and record.parent_id:
        parent = coordinator.agents.get(record.parent_id)
        if parent is not None:
            await coordinator.deliver(
                parent,
                Message(from_name=record.name, msg_type="alert", priority="high",
                        content=(f"Agent '{record.name}' ended {status.value} "
                                 f"({outcome.stop_reason}): {outcome.summary}")),
            )
    await coordinator.snapshot_async()
    coordinator.set_status(record, status, outcome.stop_reason)


async def _run_guarded(session: AgentSession) -> AgentOutcome:
    """Run one agent with crash isolation: an engine bug marks the agent
    CRASHED and alerts its parent instead of killing the whole scan."""
    record = session.record
    try:
        return await run_agent(session)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception("agent %s crashed", record.name)
        record.error = f"{type(exc).__name__}: {exc}"
        session.coordinator.set_status(record, AgentStatus.CRASHED, "unhandled exception")
        if record.parent_id:
            parent = session.coordinator.agents.get(record.parent_id)
            if parent is not None:
                await session.coordinator.deliver(
                    parent,
                    Message(from_name=record.name, msg_type="alert", priority="high",
                            content=f"Agent '{record.name}' CRASHED: {record.error}"),
                )
        return AgentOutcome(stop_reason="crashed",
                            summary=f"Agent {record.name} crashed: {exc}", finished=False)


def spawn_agent_task(session: AgentSession) -> asyncio.Task:
    """Spawn the agent's asyncio task (crash-isolated, named for debugging)."""
    return asyncio.create_task(_run_guarded(session), name=f"agent:{session.record.name}")
