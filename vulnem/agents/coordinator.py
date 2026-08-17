"""The coordinator: single owner of the multi-agent graph state.

Everything agents share lives here — the agent registry (statuses,
parent/child tree), per-agent mailboxes (a queue plus a wake event, so a
message to a parked agent revives it), the scan-wide budget, the shared
transcript, and the JSON snapshot used by ``vulnem resume``.

Design rules carried over from Strix:
- an agent ends ONLY via its lifecycle tool (``finish_scan`` for root/solo,
  ``agent_finish`` for specialists) or by coordinator intervention
  (stop / budget exhaustion / crash). Plain text never ends anything.
- ``wait_for_agents`` parks an agent exactly once — no polling loops.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from vulnem.report.findings import Finding, dedupe

logger = logging.getLogger(__name__)

SNAPSHOT_VERSION = 1


class AgentStatus(StrEnum):
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    STOPPED = "stopped"
    CRASHED = "crashed"
    FAILED = "failed"


TERMINAL_STATUSES = {
    AgentStatus.COMPLETED,
    AgentStatus.STOPPED,
    AgentStatus.CRASHED,
    AgentStatus.FAILED,
}


@dataclass(slots=True)
class Message:
    """One inter-agent message. Rendered into the target's session verbatim."""

    from_name: str
    msg_type: str  # info | instruction | alert | completion_report | system
    priority: str  # normal | high
    content: str
    ts: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))

    def render(self) -> str:
        return f"[Message from {self.from_name} | {self.msg_type} | {self.priority}]\n{self.content}"


class Budget:
    """Scan-wide budget shared by every agent (turns and tokens).

    Per-agent turn caps live on each agent record; this is the ceiling the
    whole scan may spend. ``extend`` lets an operator top up mid-run.
    """

    def __init__(self, *, max_turns: int | None = None, max_tokens: int | None = None) -> None:
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self.turns_used = 0
        self.tokens_used = 0

    @property
    def turns_exhausted(self) -> bool:
        return self.max_turns is not None and self.turns_used >= self.max_turns

    @property
    def tokens_exhausted(self) -> bool:
        return self.max_tokens is not None and self.tokens_used >= self.max_tokens

    @property
    def exhausted(self) -> bool:
        return self.turns_exhausted or self.tokens_exhausted

    def charge_turn(self) -> bool:
        """Record one LLM turn; False once over budget (still recorded)."""
        self.turns_used += 1
        return not self.exhausted

    def charge_tokens(self, n: int) -> bool:
        if n > 0:
            self.tokens_used += n
        return not self.exhausted

    def extend(self, *, max_turns: int | None = None, max_tokens: int | None = None) -> None:
        if max_turns is not None:
            self.max_turns = max(self.max_turns or 0, max_turns)
        if max_tokens is not None:
            self.max_tokens = max(self.max_tokens or 0, max_tokens)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_turns": self.max_turns,
            "max_tokens": self.max_tokens,
            "turns_used": self.turns_used,
            "tokens_used": self.tokens_used,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Budget:
        b = cls(max_turns=data.get("max_turns"), max_tokens=data.get("max_tokens"))
        b.turns_used = int(data.get("turns_used", 0))
        b.tokens_used = int(data.get("tokens_used", 0))
        return b


@dataclass
class AgentRecord:
    """Registry entry for one agent in the graph."""

    agent_id: str
    name: str
    role: str  # root | specialist | solo
    parent_id: str | None
    objective: str
    max_turns: int
    status: AgentStatus = AgentStatus.RUNNING
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S"))
    turns_used: int = 0
    total_tokens: int = 0
    completion_report: dict[str, Any] | None = None
    # root's coverage checklist (report_coverage tool); None until filed
    coverage_report: dict[str, Any] | None = None
    # finish_scan coverage bounce already used (serialized so a resumed root
    # can never be trapped by a second bounce)
    coverage_bounce_used: bool = False
    error: str | None = None
    stop_reason: str = ""
    # runtime wiring (not serialized)
    mailbox: asyncio.Queue = field(default_factory=asyncio.Queue, repr=False)
    wake_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    done_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    task: asyncio.Task | None = field(default=None, repr=False)
    session: Any | None = field(default=None, repr=False)  # AgentSession, set when spawned
    # findings loaded from a snapshot for agents that are not re-spawned
    restored_findings: list = field(default_factory=list, repr=False)

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def findings(self) -> list[Finding]:
        ctx = getattr(self.session, "ctx", None) if self.session else None
        if ctx is not None:
            return list(ctx.findings)
        return list(self.restored_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "parent_id": self.parent_id,
            "objective": self.objective,
            "max_turns": self.max_turns,
            "status": self.status.value,
            "created_at": self.created_at,
            "turns_used": self.turns_used,
            "total_tokens": self.total_tokens,
            "completion_report": self.completion_report,
            "coverage_report": self.coverage_report,
            "coverage_bounce_used": self.coverage_bounce_used,
            "error": self.error,
            "stop_reason": self.stop_reason,
        }


class Coordinator:
    """Owns the agent graph for one scan."""

    def __init__(
        self,
        *,
        run_dir: Path,
        max_agents: int = 12,
        budget: Budget | None = None,
        on_event: Any | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.max_agents = max_agents
        self.budget = budget or Budget()
        self._on_event = on_event
        self.agents: dict[str, AgentRecord] = {}
        self._by_name: dict[str, str] = {}
        self._counter = 0
        # Flipped by run_scan's operator-interrupt path BEFORE cancelling
        # agent tasks: sessions must then leave their records non-terminal
        # (snapshot as-is) so `vulnem resume` can continue them.
        self.interrupted = False
        self._status_lock = asyncio.Lock()
        # snapshot() runs in a worker thread while the loop may register
        # agents — mutations and copies of the registry are guarded.
        self._registry_lock = threading.Lock()
        self._snapshot_lock = threading.Lock()

    # -- registry ---------------------------------------------------------

    def register(
        self,
        *,
        name: str,
        role: str,
        parent_id: str | None,
        objective: str,
        max_turns: int,
    ) -> AgentRecord:
        if name in self._by_name or name == "system":
            raise ValueError(f"agent name {name!r} already in use")
        # The cap bounds LIVE (non-terminal) agents: finished specialists free
        # their slot so follow-ups can be spawned; names stay reserved forever.
        live = sum(1 for a in self.agents.values() if not a.terminal)
        if live >= self.max_agents:
            raise ValueError(
                f"agent cap reached ({self.max_agents} live); wait for a specialist "
                f"to finish, stop one with stop_agent, or finish the scan"
            )
        self._counter += 1
        record = AgentRecord(
            agent_id=f"a{self._counter}",
            name=name,
            role=role,
            parent_id=parent_id,
            objective=objective,
            max_turns=max_turns,
        )
        with self._registry_lock:
            self.agents[record.agent_id] = record
            self._by_name[name] = record.agent_id
        return record

    def resolve(self, name_or_id: str) -> AgentRecord | None:
        aid = self._by_name.get(name_or_id, name_or_id)
        return self.agents.get(aid)

    def children_of(self, agent_id: str) -> list[AgentRecord]:
        return [a for a in self.agents.values() if a.parent_id == agent_id]

    def live_children_of(self, agent_id: str) -> list[AgentRecord]:
        return [a for a in self.children_of(agent_id) if not a.terminal]

    @property
    def root(self) -> AgentRecord | None:
        return next((a for a in self.agents.values() if a.role == "root"), None)

    # -- status + events ----------------------------------------------------

    def set_status(self, record: AgentRecord, status: AgentStatus, reason: str = "") -> None:
        if record.terminal and status not in TERMINAL_STATUSES:
            return  # terminal is final
        prev = record.status
        record.status = status
        if status in TERMINAL_STATUSES:
            record.done_event.set()
            record.wake_event.set()  # release anyone parked on this record
        if prev != status:
            self.emit(
                {
                    "type": "agent_status",
                    "agent_id": record.agent_id,
                    "agent": record.name,
                    "from": prev.value,
                    "to": status.value,
                    "reason": reason,
                }
            )

    def emit(self, event: dict[str, Any]) -> None:
        """Append to the shared transcript + forward to the UI callback.

        Always called from the event-loop thread, so the append is naturally
        serialized; the write is a single small append (Phase 1 semantics).
        """
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}
        _append_line(self.run_dir / "transcript.jsonl", event)
        if self._on_event is not None:
            try:
                self._on_event(event)
            except Exception:  # UI callbacks must never kill the scan
                logger.exception("event callback failed")

    # -- mailboxes -----------------------------------------------------------

    async def deliver(self, record: AgentRecord, message: Message) -> bool:
        """Put a message in an agent's mailbox and wake it if parked."""
        if record.terminal:
            return False
        await record.mailbox.put(message)
        record.wake_event.set()
        self.emit(
            {
                "type": "agent_message",
                "from": message.from_name,
                "to": record.name,
                "to_id": record.agent_id,
                "msg_type": message.msg_type,
                "priority": message.priority,
                "preview": message.content[:200],
            }
        )
        return True

    def drain_mailbox(self, record: AgentRecord) -> list[Message]:
        """Take all pending messages (loop-side); clears the wake event after."""
        items: list[Message] = []
        while not record.mailbox.empty():
            items.append(record.mailbox.get_nowait())
        record.wake_event.clear()
        return items

    # -- wait / stop -----------------------------------------------------------

    async def wait_for(
        self, waiter: AgentRecord, agent_ids: list[str], timeout_s: float | None = None
    ) -> dict[str, Any]:
        """Park ``waiter`` until every listed agent is terminal.

        Blocks exactly once (no polling): wakes on all-done, on a message
        arriving for the waiter, or on timeout — whichever comes first.
        """
        self.set_status(waiter, AgentStatus.WAITING, f"waiting for {agent_ids}")
        try:
            while True:
                if not waiter.mailbox.empty():
                    return {"ok": True, "woken_by": "message",
                            "note": "a message arrived while waiting; it will be "
                                    "delivered on your next turn"}
                pending = [self.agents[i] for i in agent_ids
                           if i in self.agents and not self.agents[i].terminal]
                if not pending:
                    return {"ok": True, "woken_by": "all_done", "agents": self._wait_results(agent_ids)}
                waitables = [asyncio.ensure_future(a.done_event.wait()) for a in pending]
                waitables.append(asyncio.ensure_future(waiter.wake_event.wait()))
                done, _ = await asyncio.wait(
                    waitables, timeout=timeout_s, return_when=asyncio.FIRST_COMPLETED
                )
                for t in waitables:
                    t.cancel()
                if not done:
                    return {"ok": True, "woken_by": "timeout",
                            "still_running": [a.name for a in pending],
                            "agents": self._wait_results(agent_ids)}
        finally:
            if not waiter.terminal:
                self.set_status(waiter, AgentStatus.RUNNING, "wait finished")

    def _wait_results(self, agent_ids: list[str]) -> list[dict[str, Any]]:
        out = []
        for aid in agent_ids:
            a = self.agents.get(aid)
            if a is None:
                continue
            entry: dict[str, Any] = {
                "id": a.agent_id,
                "name": a.name,
                "status": a.status.value,
                "turns_used": a.turns_used,
                "findings": [
                    {"title": f.title, "severity": f.severity, "url": f.url or ""}
                    for f in a.findings()
                ],
            }
            if a.completion_report:
                entry["completion_report"] = a.completion_report
            if a.error:
                entry["error"] = a.error
            out.append(entry)
        return out

    async def stop_agent(self, record: AgentRecord, reason: str) -> str:
        """Force-stop one agent: mark stopped, cancel its task, alert the parent."""
        if record.terminal:
            return f"agent {record.name} already {record.status.value}"
        record.stop_reason = record.stop_reason or reason
        self.set_status(record, AgentStatus.STOPPED, reason)
        if record.task is not None and not record.task.done():
            record.task.cancel()
        if record.parent_id:
            parent = self.agents.get(record.parent_id)
            if parent is not None:
                await self.deliver(
                    parent,
                    Message(from_name=record.name, msg_type="alert", priority="high",
                            content=f"Agent '{record.name}' was stopped: {reason}"),
                )
        return f"agent {record.name} stopped: {reason}"

    # -- findings -------------------------------------------------------------

    def collect_findings(self) -> list[Finding]:
        """All findings from every agent, deduped cross-agent and renumbered."""
        collected: list[Finding] = []
        for record in self.agents.values():
            collected.extend(record.findings())
        merged = dedupe(collected)
        for i, f in enumerate(merged, start=1):
            f.id = f"VULN-{i:03d}"
        return merged

    # -- graph view ---------------------------------------------------------------

    def graph_view(self) -> str:
        lines: list[str] = []

        def describe(a: AgentRecord) -> str:
            bits = [f"{a.name} ({a.agent_id}, {a.role}) [{a.status.value}]",
                    f"turns {a.turns_used}/{a.max_turns}",
                    f"tokens {a.total_tokens}"]
            n_findings = len(a.findings())
            if n_findings:
                bits.append(f"findings {n_findings}")
            if a.completion_report:
                bits.append(f"report: {a.completion_report.get('status', '?')}")
            if a.error:
                bits.append(f"error: {a.error[:120]}")
            return " · ".join(bits)

        roots = [a for a in self.agents.values() if a.parent_id is None]
        def render(a: AgentRecord, prefix: str) -> None:
            lines.append(prefix + describe(a))
            kids = sorted(self.children_of(a.agent_id), key=lambda c: c.created_at)
            for i, kid in enumerate(kids):
                connector = "└─ " if i == len(kids) - 1 else "├─ "
                render(kid, prefix + connector)

        for r in roots:
            render(r, "")
        budget_line = f"scan budget: {self.budget.turns_used}"
        if self.budget.max_turns is not None:
            budget_line += f"/{self.budget.max_turns} turns"
        else:
            budget_line += " turns (no cap)"
        lines.append(budget_line)
        return "\n".join(lines)

    # -- snapshot / restore ----------------------------------------------------

    def snapshot(self) -> None:
        """Persist graph state + every agent session for ``vulnem resume``.

        Serialized: several agents can finalize concurrently and each
        snapshot rewrites the full state — interleaved writes corrupt it.
        """
        with self._snapshot_lock:
            self._write_snapshot()

    def _write_snapshot(self) -> None:
        with self._registry_lock:
            records = list(self.agents.values())
        state = {
            "version": SNAPSHOT_VERSION,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "max_agents": self.max_agents,
            "budget": self.budget.to_dict(),
            "agents": [a.to_dict() for a in records],
        }
        (self.run_dir / "state.json").write_text(
            json.dumps(state, indent=2), encoding="utf-8"
        )
        sessions_dir = self.run_dir / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        for record in records:
            if record.session is None:
                continue
            payload = {
                "agent_id": record.agent_id,
                "messages": getattr(record.session, "messages", []),
                "findings": [f.model_dump() for f in record.findings()],
            }
            (sessions_dir / f"{record.agent_id}.json").write_text(
                json.dumps(payload, indent=2, default=str), encoding="utf-8"
            )

    async def snapshot_async(self) -> None:
        await asyncio.to_thread(self.snapshot)

    @classmethod
    def load_state(cls, run_dir: Path) -> dict[str, Any]:
        path = run_dir / "state.json"
        if not path.is_file():
            raise FileNotFoundError(f"no state.json in {run_dir}")
        return json.loads(path.read_text(encoding="utf-8"))

    @classmethod
    def load_session(cls, run_dir: Path, agent_id: str) -> dict[str, Any]:
        path = run_dir / "sessions" / f"{agent_id}.json"
        if not path.is_file():
            raise FileNotFoundError(f"no session file for {agent_id}")
        return json.loads(path.read_text(encoding="utf-8"))


def _append_line(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
