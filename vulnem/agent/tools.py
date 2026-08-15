"""Tools the scan agent can call, plus the dispatcher that runs them."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnem.config import Settings
from vulnem.report.findings import Finding, dedupe
from vulnem.sandbox import Sandbox
from vulnem.textutil import truncate as truncate  # re-exported for callers/tests

logger = logging.getLogger(__name__)

FINISH_TOOL = "finish_scan"


@dataclass(slots=True)
class ToolContext:
    """Everything tool implementations need, owned by the agent session."""

    settings: Settings
    sandbox: Sandbox
    scope_host: str
    findings: list[Finding] = field(default_factory=list)
    transcript_events: list[dict[str, Any]] = field(default_factory=list)
    agent_name: str = ""  # set by the session; stamps findings + transcripts
    # Phase 3 plumbing (all optional so older constructions keep working):
    allowed_hosts: tuple[str, ...] = ()  # system-verified scope (browser tools)
    proxy: Any = None                     # ProxyManager (proxy tools)
    sandbox_proxy_url: str | None = None  # sidecar URL as seen from the sandbox
    auth_cookies: list[dict[str, Any]] = field(default_factory=list)  # seeded session
    run_dir: Path | None = None           # artifacts land in run_dir/artifacts/
    emit_event: Callable[[dict[str, Any]], None] | None = None  # session hook

    def record(self, event: dict[str, Any]) -> None:
        self.transcript_events.append(event)
        if self.emit_event is not None:
            self.emit_event(event)


# -- OpenAI-format tool schemas ------------------------------------------------

# Hands-on tools: every tool whose handler is a plain sync function run in a
# worker thread (graph tools live in vulnem/agents/graph_tools.py). The
# Phase 3 browser + proxy tools follow the same sync pattern.
from vulnem.tools.browser import BROWSER_HANDLERS, BROWSER_SCHEMAS  # noqa: E402
from vulnem.tools.proxy import PROXY_HANDLERS, PROXY_SCHEMAS  # noqa: E402

HANDS_ON_TOOL_NAMES = (
    {"exec_command", "read_skill", "report_finding", "think"}
    | set(BROWSER_SCHEMAS)
    | set(PROXY_SCHEMAS)
)

SCHEMA_BY_NAME: dict[str, dict[str, Any]] = {
    "exec_command": {
        "type": "function",
        "function": {
            "name": "exec_command",
            "description": (
                "Run a shell command inside the isolated sandbox and return "
                "exit code, stdout, and stderr. Non-interactive tools only; "
                "long output is truncated (write to a file and grep to narrow)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The bash command to execute.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": f"Optional timeout in seconds (default {120}, max 600).",
                    },
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        },
    },
    "read_skill": {
        "type": "function",
        "function": {
            "name": "read_skill",
            "description": (
                "Load a methodology knowledge pack into context. Call with no "
                "name to list available skills. Read `recon` before testing; "
                "read the class-specific skill before testing that class."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Skill name (from the list), or omit to list skills.",
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    },
    "report_finding": {
        "type": "function",
        "function": {
            "name": "report_finding",
            "description": (
                "File a VALIDATED vulnerability finding. Only call this after "
                "reproducing the issue and capturing evidence. PoC must let a "
                "human reproduce it step by step; evidence must contain the "
                "actual command and response output."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short, specific title."},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "poc": {"type": "string"},
                    "remediation": {"type": "string"},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                    "cwe": {
                        "type": "string",
                        "description": "Optional CWE id, e.g. CWE-89.",
                    },
                    "cvss_vector": {
                        "type": "string",
                        "description": (
                            "Optional CVSS vector, e.g. "
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        ),
                    },
                    "cvss_score": {
                        "type": "number",
                        "description": "Optional CVSS base score 0.0-10.0 matching the vector.",
                    },
                    "url": {"type": "string", "description": "Affected URL (enables cross-agent dedupe)."},
                },
                "required": [
                    "title",
                    "severity",
                    "description",
                    "evidence",
                    "poc",
                    "remediation",
                ],
                "additionalProperties": False,
            },
        },
    },
    "think": {
        "type": "function",
        "function": {
            "name": "think",
            "description": (
                "Private scratchpad for planning. Use it to lay out the next "
                "hypothesis, interpret confusing output, or decide priorities. "
                "Cheap; use freely instead of long plain-text narration."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "thoughts": {"type": "string"},
                },
                "required": ["thoughts"],
                "additionalProperties": False,
            },
        },
    },
}

# Kept for Phase 1 compatibility (solo toolset without lifecycle tools).
TOOL_SCHEMAS: list[dict[str, Any]] = list(SCHEMA_BY_NAME.values())

# Phase 3 tool surfaces merge into the shared registry (browser = stateful
# headless Chromium per agent; proxy = mitmproxy traffic inspection/replay).
SCHEMA_BY_NAME.update(BROWSER_SCHEMAS)
SCHEMA_BY_NAME.update(PROXY_SCHEMAS)


# -- Implementations -----------------------------------------------------------


def _list_skills(skills_dir: Path) -> list[dict[str, str]]:
    """List skill packs recursively; names are paths relative to skills_dir."""
    packs: list[dict[str, str]] = []
    if not skills_dir.is_dir():
        return packs
    for path in sorted(skills_dir.rglob("*.md")):
        description = ""
        text = path.read_text(encoding="utf-8")
        if text.startswith("---"):
            frontmatter, _, _ = text[3:].partition("---")
            for line in frontmatter.splitlines():
                if line.lower().startswith("description:"):
                    description = line.partition(":")[2].strip()
                    break
        packs.append({"name": path.relative_to(skills_dir).with_suffix("").as_posix(),
                      "description": description})
    return packs


def _tool_exec_command(ctx: ToolContext, args: dict[str, Any]) -> str:
    command = str(args.get("command", "")).strip()
    if not command:
        return json.dumps({"exit_code": 2, "stdout": "", "stderr": "empty command"})
    timeout = max(1, min(int(args.get("timeout") or 120), 600))
    res = ctx.sandbox.exec(command, timeout=timeout)
    payload = {
        "exit_code": res.exit_code,
        "stdout": truncate(res.stdout),
        "stderr": truncate(res.stderr),
        "duration_s": round(res.duration, 1),
    }
    return json.dumps(payload, ensure_ascii=False)


def _tool_read_skill(ctx: ToolContext, args: dict[str, Any]) -> str:
    name = str(args.get("name") or "").strip()
    packs = _list_skills(ctx.settings.skills_dir)
    if not name:
        listing = "\n".join(f"- {p['name']}: {p['description']}" for p in packs)
        return f"Available skills:\n{listing or '(none found)'}"
    # Allow nested names (coordination/root_agent) but never escape skills_dir.
    safe = Path(*[part for part in Path(name).parts if part not in ("..", "/", "\\")])
    path = (ctx.settings.skills_dir / safe).with_suffix(".md")
    if not path.is_file():
        return f"Skill '{name}' not found. List skills by calling read_skill with no name."
    return truncate(path.read_text(encoding="utf-8"), 24_000)


def _tool_report_finding(ctx: ToolContext, args: dict[str, Any]) -> str:
    try:
        finding = Finding(
            title=str(args["title"]),
            severity=str(args["severity"]),
            description=str(args["description"]),
            evidence=str(args["evidence"]),
            poc=str(args["poc"]),
            remediation=str(args["remediation"]),
            confidence=str(args.get("confidence") or "high"),
            cwe=args.get("cwe") or None,
            url=args.get("url") or None,
            cvss_vector=args.get("cvss_vector") or None,
            cvss_score=args.get("cvss_score"),
            reported_by=ctx.agent_name or "solo-agent",
        )
    except (KeyError, ValueError) as exc:
        return json.dumps({"ok": False, "error": f"invalid finding: {exc}"})
    finding.id = f"VULN-{len(ctx.findings) + 1:03d}"
    ctx.findings.append(finding)
    logger.info("finding reported: [%s] %s", finding.severity, finding.title)
    return json.dumps(
        {"ok": True, "id": finding.id, "total_findings": len(ctx.findings)},
    )


def _tool_think(_ctx: ToolContext, args: dict[str, Any]) -> str:
    thoughts = str(args.get("thoughts") or "")
    return json.dumps({"ok": True, "note": "recorded", "chars": len(thoughts)})


def _tool_finish(ctx: ToolContext, args: dict[str, Any]) -> str:
    summary = str(args.get("summary") or "(no summary provided)")
    ctx.record({"type": "finish", "summary": summary})
    return json.dumps({"ok": True, "note": "scan finishing"})


def dispatch_tool(name: str, args: dict[str, Any], ctx: ToolContext) -> str:
    """Run one tool call; always returns a JSON string for the model."""
    handlers: dict[str, Callable[[ToolContext, dict[str, Any]], str]] = {
        "exec_command": _tool_exec_command,
        "read_skill": _tool_read_skill,
        "report_finding": _tool_report_finding,
        "think": _tool_think,
        FINISH_TOOL: _tool_finish,
        **BROWSER_HANDLERS,
        **PROXY_HANDLERS,
    }
    handler = handlers.get(name)
    if handler is None:
        return json.dumps({"ok": False, "error": f"unknown tool {name!r}"})
    try:
        return handler(ctx, args)
    except Exception as exc:  # tool failures go back to the model, never crash the loop
        logger.exception("tool %s failed", name)
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def final_findings(ctx: ToolContext) -> list[Finding]:
    return dedupe(ctx.findings)
