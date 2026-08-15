"""End-to-end plumbing test with a scripted fake LLM.

Runs the FULL stack — demo lab (Juice Shop on an internal network), sandbox,
agent loop, tool dispatch, report writing — with litellm.completion replaced
by a canned script. Proves everything except the paid model call works.
Usage:  .venv/Scripts/python scripts/mock_e2e.py
"""

from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# (assistant_text, tool_name, tool_args_json) — {TARGET} is replaced with the
# real lab URL scraped from the conversation on each call.
SCRIPT: list[tuple[str, str, str]] = [
    ("Planning the assessment.", "think", {"thoughts": "map target, probe, report, finish"}),
    ("", "read_skill", {"name": "recon"}),
    ("Probing the target.", "exec_command",
     {"command": "curl -s -o /dev/null -w '%{http_code}' {TARGET}"}),
    ("Checking a sensitive path.", "exec_command",
     {"command": "curl -s -o /dev/null -w '%{http_code}' {TARGET}/ftp"}),
    ("Capturing evidence.", "exec_command",
     {"command": "curl -s {TARGET}/rest/products/search?q=orange' | head -c 300"}),
    ("Filing the finding.", "report_finding", {
        "title": "E2E plumbing-test finding (reflection in search API)",
        "severity": "low",
        "description": "Mock finding produced by scripts/mock_e2e.py to verify the "
                       "report pipeline end to end; not a real vulnerability verdict.",
        "evidence": "curl output captured by the scripted agent during the mock run.",
        "poc": "curl -s '{TARGET}/rest/products/search?q=orange'",
        "remediation": "Ignore — plumbing test artifact.",
        "confidence": "low",
    }),
    ("Scan complete.", "finish_scan", {"summary": "Mock E2E scan: plumbing verified."}),
]


def _make_response(idx: int, text: str, name: str, args: str):
    tc = types.SimpleNamespace(
        id=f"call_{idx}",
        function=types.SimpleNamespace(name=name, arguments=args),
    )
    message = types.SimpleNamespace(content=text, tool_calls=[tc])
    usage = types.SimpleNamespace(prompt_tokens=100, completion_tokens=20)
    return types.SimpleNamespace(
        choices=[types.SimpleNamespace(message=message)], usage=usage
    )


_queue = list(enumerate(SCRIPT))


def _substitute(obj, target: str):
    if isinstance(obj, str):
        return obj.replace("{TARGET}", target)
    if isinstance(obj, dict):
        return {k: _substitute(v, target) for k, v in obj.items()}
    return obj


def _fake_completion(**kwargs):
    if not _queue:
        raise RuntimeError("script exhausted before finish_scan")
    idx, (text, name, args) = _queue.pop(0)
    target = ""
    for m in reversed(kwargs.get("messages", [])):
        content = getattr(m, "content", None) or (m.get("content") if isinstance(m, dict) else "")
        if content and "http://" in str(content):
            target = re.search(r"http://\S+", str(content)).group(0).rstrip(".\n")
            break
    return _make_response(idx, text, name, json.dumps(_substitute(args, target)))


def main() -> int:
    import litellm

    litellm.completion = _fake_completion  # type: ignore[assignment]

    from vulnem.cli import PROJECT_ROOT as ROOT
    from vulnem.cli import _resolve_paths, _run_demo
    from vulnem.config import Settings

    settings = _resolve_paths(Settings.load(project_root=ROOT))
    settings.yes = True
    return _run_demo(settings)


if __name__ == "__main__":
    sys.exit(main())
