"""Pure transcript reducer: turns ``transcript.jsonl`` events into view state.

No UI dependency — this module is what the Textual app renders and what the
tests verify. Every event type the engine emits has a home here; unknown
types degrade to a one-line system entry instead of being dropped, so the
UI never lags the transcript schema.
"""

from __future__ import annotations

import json
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path

TERMINAL_STATUSES = {"completed", "stopped", "crashed", "failed"}
# agent_end.stop_reason -> status when no agent_status event said otherwise
_STOP_REASON_STATUS = {
    "finish_tool": "completed",
    "agent_finish": "completed",
    "budget": "stopped",
    "scan_budget": "stopped",
    "token_budget": "stopped",
    "max_turns": "stopped",
    "stalled": "stopped",
    "stopped": "stopped",
    "crashed": "crashed",
    "error": "failed",
}
SEVERITY_TONES = {"critical": "critical", "high": "critical", "medium": "warn",
                  "low": "info", "info": "info"}


def _shorten(text: object, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def format_tool_call(name: str, args: dict) -> str:
    """One-line summary of a tool call for the stream (plain text, no markup)."""
    if name == "exec_command":
        return f"exec  {_shorten(args.get('command', ''), 120)}"
    if name == "think":
        return f"think  {_shorten(args.get('thoughts', ''), 90)}"
    if name == "read_skill":
        return f"skill  {args.get('name', '(list)')}"
    if name == "report_finding":
        sev = str(args.get("severity", "?")).upper()
        return f"finding [{sev}]  {args.get('title', '')}"
    if name.startswith("browser_"):
        detail = (args.get("url") or args.get("selector") or args.get("expression")
                  or args.get("label") or "")
        return f"{name.replace('browser_', 'browser.')}  {_shorten(str(detail), 100)}"
    if name in {"list_requests", "view_request", "repeat_request", "view_sitemap"}:
        return f"{name}  {args.get('id', args.get('q', ''))}"
    if name == "create_agent":
        return f"create_agent  {args.get('name', '?')} — {_shorten(args.get('objective', ''), 100)}"
    if name == "wait_for_agents":
        return f"wait_for_agents  {args.get('agent_ids') or '(all children)'}"
    if name in {"finish_scan", "agent_finish"}:
        return name
    return name


@dataclass(slots=True)
class AgentView:
    agent_id: str
    name: str
    role: str = "specialist"
    parent_id: str | None = None
    objective: str = ""
    status: str = "pending"
    turns: int = 0
    tokens: int = 0
    findings: int = 0
    stop_reason: str = ""


@dataclass(slots=True)
class StreamItem:
    ts: str
    agent: str
    tone: str  # text | tool | finding | agent | msg | warn | sys | critical
    text: str


@dataclass(slots=True)
class FindingView:
    title: str
    severity: str
    url: str
    by: str
    turn: int = 0


@dataclass
class RunState:
    """Everything the UI shows, derived purely from transcript events."""

    target: str = ""
    model: str = ""
    mode: str = ""
    budget_turns: int | None = None
    proxy: bool = False
    authenticated: bool = False
    resumed: bool = False
    started_at: str = ""
    ended_at: str = ""
    stop_reason: str = ""
    turns_used: int = 0
    total_tokens: int = 0
    findings_total: int | None = None  # authoritative count from scan_end

    agents: dict[str, AgentView] = field(default_factory=dict)
    stream: deque[StreamItem] = field(default_factory=lambda: deque(maxlen=4000))
    findings: list[FindingView] = field(default_factory=list)
    screenshots: list[dict] = field(default_factory=list)
    messages: deque[StreamItem] = field(default_factory=lambda: deque(maxlen=200))
    flow_count: int = 0
    flow_hosts: Counter = field(default_factory=Counter)
    blocked_count: int = 0
    blocked: list[dict] = field(default_factory=list)
    auth: dict | None = None
    events_seen: int = 0

    # -- ingestion ------------------------------------------------------------

    def apply(self, event: dict) -> None:
        self.events_seen += 1
        kind = event.get("type", "?")
        handler = getattr(self, f"_on_{kind}", None)
        if handler is not None:
            handler(event)
        else:
            self._sys(event, f"{kind}  {_shorten(json.dumps(event, default=str), 100)}")

    def apply_all(self, events) -> None:
        for event in events:
            self.apply(event)

    @classmethod
    def from_transcript(cls, path: Path) -> RunState:
        state = cls()
        state.apply_all(_iter_events(path))
        return state

    # -- lookups --------------------------------------------------------------

    def agent(self, event: dict) -> AgentView:
        ctx = event.get("agent_ctx") or {}
        agent_id = ctx.get("id") or event.get("agent_id") or "?"
        view = self.agents.get(agent_id)
        if view is None:
            view = AgentView(agent_id=agent_id, name=ctx.get("name") or agent_id,
                             role=ctx.get("role", "specialist"),
                             parent_id=ctx.get("parent_id"))
            self.agents[agent_id] = view
        return view

    def live_agents(self) -> list[AgentView]:
        return [a for a in self.agents.values() if a.status not in TERMINAL_STATUSES]

    def severity_counts(self) -> dict[str, int]:
        counts = Counter(f.severity for f in self.findings)
        return dict(counts)

    # -- helpers --------------------------------------------------------------

    def _sys(self, event: dict, text: str, tone: str = "sys") -> None:
        self.stream.append(StreamItem(event.get("ts", ""), "", tone, text))

    def _tagged(self, event: dict, text: str, tone: str = "tool") -> None:
        view = self.agent(event)
        self.stream.append(StreamItem(event.get("ts", ""), view.name, tone, text))

    # -- event handlers ---------------------------------------------------------

    def _on_scan_start(self, e: dict) -> None:
        self.target = e.get("target", "")
        self.model = e.get("model", "")
        self.mode = e.get("mode", "")
        self.budget_turns = e.get("budget_turns")
        self.proxy = bool(e.get("proxy"))
        self.authenticated = bool(e.get("authenticated"))
        self.resumed = bool(e.get("resumed"))
        self.started_at = e.get("ts", "")
        self._sys(e, f"scan start  {self.target}  ({self.model}, {self.mode} mode, "
                     f"budget {self.budget_turns} turns"
                     + (", resumed" if self.resumed else "") + ")")

    def _on_scan_end(self, e: dict) -> None:
        self.stop_reason = e.get("stop_reason", "")
        self.turns_used = int(e.get("turns_used") or 0)
        self.total_tokens = int(e.get("total_tokens") or 0)
        self.findings_total = int(e.get("findings") or 0)
        self.ended_at = e.get("ts", "")
        self._sys(e, f"scan end  ({self.stop_reason})  turns {self.turns_used}, "
                     f"tokens {self.total_tokens:,}, findings {self.findings_total}")

    def _on_agent_created(self, e: dict) -> None:
        agent_id = e.get("agent_id", "?")
        view = self.agents.get(agent_id)
        if view is None:
            view = AgentView(agent_id=agent_id, name=e.get("agent", agent_id),
                             parent_id=e.get("parent_id"))
            self.agents[agent_id] = view
        view.objective = e.get("objective", view.objective)
        parent = self.agents.get(view.parent_id or "")
        self.stream.append(StreamItem(e.get("ts", ""), parent.name if parent else "",
                                      "agent", f"+ {view.name} spawned"
                                      + (f" by {parent.name}" if parent else "")))

    def _on_agent_start(self, e: dict) -> None:
        view = self.agent(e)
        view.objective = e.get("objective", view.objective) or view.objective
        if view.status in ("pending",):
            view.status = "running"
        self._tagged(e, f"agent start  {_shorten(view.objective, 100)}", "agent")

    def _on_agent_status(self, e: dict) -> None:
        view = self.agent(e)
        view.status = str(e.get("to", view.status))
        reason = e.get("reason")
        self.stream.append(StreamItem(e.get("ts", ""), view.name, "agent",
                                      f"→ {view.status}" + (f"  ({reason})" if reason else "")))

    def _on_agent_end(self, e: dict) -> None:
        view = self.agent(e)
        view.turns = max(view.turns, int(e.get("turns_used") or 0))
        view.tokens = max(view.tokens, int(e.get("total_tokens") or 0))
        view.findings = max(view.findings, int(e.get("findings") or 0))
        view.stop_reason = e.get("stop_reason", "")
        if view.status not in TERMINAL_STATUSES:
            view.status = _STOP_REASON_STATUS.get(view.stop_reason, "completed")
        self._tagged(e, f"agent end ({view.stop_reason})  turns {view.turns}, "
                        f"tokens {view.tokens:,}, findings {view.findings}", "agent")

    def _on_tool_call(self, e: dict) -> None:
        view = self.agent(e)
        view.turns = max(view.turns, int(e.get("turn") or 0))
        name = e.get("name", "?")
        args = e.get("args") or {}
        self._tagged(e, format_tool_call(name, args))
        if name == "report_finding":
            self.findings.append(FindingView(
                title=str(args.get("title", "(untitled)")),
                severity=str(args.get("severity", "info")).lower(),
                url=str(args.get("url") or ""),
                by=view.name,
                turn=int(e.get("turn") or 0),
            ))

    def _on_tool_result(self, e: dict) -> None:
        # results stay off the stream (too verbose); agents' progress is
        # visible through their next calls. Counted via turns already.
        pass

    def _on_assistant_text(self, e: dict) -> None:
        self._tagged(e, _shorten(e.get("text", ""), 200), "text")

    def _on_agent_message(self, e: dict) -> None:
        item = StreamItem(e.get("ts", ""), str(e.get("from", "?")), "msg",
                          f"→ {e.get('to', '?')}: {_shorten(e.get('preview', ''), 90)}")
        self.stream.append(item)
        self.messages.append(item)

    def _on_message_delivered(self, e: dict) -> None:
        view = self.agent(e)
        self.stream.append(StreamItem(
            e.get("ts", ""), view.name, "msg",
            f"received: {_shorten(e.get('preview', ''), 90)}"))

    def _on_nudge(self, e: dict) -> None:
        self._tagged(e, f"nudge  {_shorten(e.get('text', ''), 90)}", "sys")

    def _on_screenshot(self, e: dict) -> None:
        shot = {"artifact": e.get("artifact", ""), "bytes": int(e.get("bytes") or 0)}
        self.screenshots.append(shot)
        self._tagged(e, f"screenshot  {shot['artifact']} ({shot['bytes']:,} bytes)")

    def _on_proxy_started(self, e: dict) -> None:
        self._sys(e, f"proxy sidecar {e.get('sidecar', '?')} up "
                     f"(scope: {', '.join(e.get('scope_hosts') or []) or 'any'})")

    def _on_proxy_flow(self, e: dict) -> None:
        self.flow_count += 1
        host = e.get("host")
        if host:
            self.flow_hosts[host] += 1

    def _on_scope_blocked(self, e: dict) -> None:
        self.blocked_count += 1
        entry = {"layer": e.get("layer", "?"), "method": e.get("method", ""),
                 "host": e.get("host") or e.get("url", "")}
        self.blocked.append(entry)
        self._sys(e, f"SCOPE BLOCK ({entry['layer']})  {entry['method']} {entry['host']}",
                  "warn")

    def _on_auth_established(self, e: dict) -> None:
        self.auth = e
        state = "ok" if e.get("ok") else "FAILED"
        cookies = ", ".join(e.get("cookie_names") or []) or "none"
        self._sys(e, f"auth session {state} via {e.get('method', '?')} "
                     f"(cookies: {cookies})")


def _iter_events(path: Path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue  # torn tail line while the scan is still writing


def replay_speed_for(event_count: int) -> int:
    """Events/sec that replays any run in roughly 40s (min 40/s, 0 for empty)."""
    if event_count <= 0:
        return 0
    return max(40, -(-event_count // 40))
