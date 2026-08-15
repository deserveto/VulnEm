"""The scan agent loop: LLM turns, tool dispatch, lifecycle, transcript.

Deliberately hand-rolled on litellm instead of using an agent framework:
Phase 1 is a single agent, and a transparent ~250-line loop is easier to
debug, extend, and later port than SDK magic. The loop only ends via the
``finish_scan`` tool (Strix's most important lifecycle lesson — plain text
never ends a turn).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnem.agent.prompt import build_initial_task, build_system_prompt
from vulnem.agent.tools import (
    FINISH_TOOL,
    TOOL_SCHEMAS,
    ToolContext,
    dispatch_tool,
    final_findings,
)
from vulnem.config import Settings
from vulnem.report.findings import Finding
from vulnem.sandbox import Sandbox
from vulnem.scope import Scope

logger = logging.getLogger(__name__)

# litellm retries transient provider errors itself; these are for the rest.
_COMPLETION_TIMEOUT_S = 300
_MAX_PROVIDER_RETRIES = 3
_MAX_TEXT_ONLY_TURNS = 3

EventCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class ScanResult:
    finished: bool
    stop_reason: str  # finish_tool | max_turns | token_budget | stalled | error
    summary: str
    findings: list[Finding] = field(default_factory=list)
    turns_used: int = 0
    total_tokens: int = 0
    transcript_path: Path | None = None


class ScanAgent:
    """One scan: system prompt + tools + a sandbox, driven to completion."""

    def __init__(
        self,
        *,
        scope: Scope,
        settings: Settings,
        sandbox: Sandbox,
        transcript_path: Path | None = None,
        on_event: EventCallback | None = None,
    ) -> None:
        self._scope = scope
        self._settings = settings
        self._sandbox = sandbox
        self._transcript_path = transcript_path
        self._on_event = on_event
        self._ctx = ToolContext(settings=settings, sandbox=sandbox, scope_host=scope.host)
        self._messages: list[dict[str, Any]] = [
            {"role": "system", "content": build_system_prompt(scope, max_turns=settings.max_turns)},
            {"role": "user", "content": build_initial_task(scope)},
        ]
        self._turns_used = 0
        self._total_tokens = 0

    # -- internals -----------------------------------------------------------

    def _emit(self, event: dict[str, Any]) -> None:
        event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}
        if self._transcript_path is not None:
            with self._transcript_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        if self._on_event is not None:
            try:
                self._on_event(event)
            except Exception:  # UI callbacks must never kill the scan
                logger.exception("event callback failed")

    def _completion(self):
        """One LLM call with basic retry on transient provider failures."""
        import litellm

        last_exc: Exception | None = None
        for attempt in range(_MAX_PROVIDER_RETRIES):
            try:
                return litellm.completion(
                    model=self._settings.model,
                    messages=self._messages,  # type: ignore[arg-type]
                    tools=TOOL_SCHEMAS,
                    timeout=_COMPLETION_TIMEOUT_S,
                    num_retries=2,
                )
            except Exception as exc:
                last_exc = exc
                logger.warning("completion attempt %d failed: %s", attempt + 1, exc)
                time.sleep(2**attempt)
        raise RuntimeError(f"LLM call failed after {_MAX_PROVIDER_RETRIES} attempts") from last_exc

    # -- main loop ------------------------------------------------------------

    def run(self) -> ScanResult:
        stop_reason = "error"
        summary = ""
        finished = False
        text_only_streak = 0

        self._emit({"type": "scan_start", "target": self._scope.target_url,
                    "model": self._settings.model})

        try:
            while self._turns_used < self._settings.max_turns:
                if self._total_tokens >= self._settings.max_total_tokens:
                    stop_reason = "token_budget"
                    summary = "Scan stopped: total token budget exhausted."
                    break

                self._turns_used += 1
                response = self._completion()

                usage = getattr(response, "usage", None)
                if usage is not None:
                    self._total_tokens += int(
                        getattr(usage, "prompt_tokens", 0) or 0
                    ) + int(getattr(usage, "completion_tokens", 0) or 0)

                message = response.choices[0].message
                tool_calls = getattr(message, "tool_calls", None) or []
                text = (getattr(message, "content", None) or "").strip()
                if text:
                    self._emit({"type": "assistant_text", "turn": self._turns_used,
                                "text": text})

                if not tool_calls:
                    text_only_streak += 1
                    if text_only_streak >= _MAX_TEXT_ONLY_TURNS:
                        stop_reason = "stalled"
                        summary = (
                            "Scan stopped: agent produced several consecutive turns "
                            "without calling any tool."
                        )
                        break
                    self._messages.append(
                        {"role": "user", "content": (
                            "[system] Your last turns had no tool call. Every turn must "
                            f"end with exactly one tool call. Call `{FINISH_TOOL}` with a "
                            "summary if testing is complete.")}
                    )
                    self._emit({"type": "nudge", "turn": self._turns_used,
                                "streak": text_only_streak})
                    continue

                text_only_streak = 0
                # Append the assistant message verbatim so tool results link correctly.
                self._messages.append(message)  # type: ignore[arg-type]

                for tc in tool_calls:
                    name = tc.function.name
                    raw_args = tc.function.arguments
                    try:
                        # Providers (and test doubles) deliver args as a JSON
                        # string or an already-parsed dict — accept both.
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
                        result = json.dumps({"ok": False,
                                             "error": f"invalid tool arguments JSON: {exc}"})
                    else:
                        self._emit({"type": "tool_call", "turn": self._turns_used,
                                    "name": name, "args": args})
                        result = dispatch_tool(name, args, self._ctx)
                    self._emit({"type": "tool_result", "turn": self._turns_used,
                                "name": name, "result": result})
                    self._messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result,
                    })
                    if name == FINISH_TOOL:
                        stop_reason = "finish_tool"
                        finished = True
                        summary = str(args.get("summary") or summary)
                        break
                if finished:
                    break
            else:
                stop_reason = "max_turns"
                summary = summary or "Scan stopped: maximum number of turns reached."
        except KeyboardInterrupt:
            stop_reason = "interrupted"
            summary = "Scan interrupted by operator."
        except Exception as exc:
            logger.exception("scan loop failed")
            stop_reason = "error"
            summary = f"Scan aborted by error: {exc}"

        self._emit({
            "type": "scan_end",
            "stop_reason": stop_reason,
            "turns_used": self._turns_used,
            "total_tokens": self._total_tokens,
            "findings": len(final_findings(self._ctx)),
        })
        return ScanResult(
            finished=finished,
            stop_reason=stop_reason,
            summary=summary,
            findings=final_findings(self._ctx),
            turns_used=self._turns_used,
            total_tokens=self._total_tokens,
            transcript_path=self._transcript_path,
        )


def run_scan_agent(
    *,
    scope: Scope,
    settings: Settings,
    sandbox: Sandbox,
    transcript_path: Path | None = None,
    on_event: EventCallback | None = None,
) -> ScanResult:
    """Convenience wrapper: build and run a ScanAgent in one call."""
    agent = ScanAgent(
        scope=scope,
        settings=settings,
        sandbox=sandbox,
        transcript_path=transcript_path,
        on_event=on_event,
    )
    return agent.run()
