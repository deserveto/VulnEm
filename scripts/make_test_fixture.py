"""Generate tests/fixtures/run/ — a compact, committed stand-in for a real
runs/<id> directory so CI (fresh checkout, no runs/) can exercise the TUI
reducer, SARIF/PDF export, and eval-cost code paths. Regenerate with:
`.venv/Scripts/python scripts/make_test_fixture.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "run"


def ev(ts: str, type_: str, **kw) -> dict:
    return {"ts": f"2026-08-16T{ts}", "type": type_, **kw}


def build_transcript() -> list[dict]:
    events = [
        ev("10:00:00", "proxy_started", sidecar="vulnem-proxy-fixture",
           network="vulnem-lab_labnet", scope_hosts=["juice-shop"]),
        ev("10:00:00", "auth_established", ok=True, method="api",
           detail="API login ok", cookie_names=["token"], has_bearer=True,
           storage_keys=[], login_url="http://juice-shop:3000/#/login"),
        ev("10:00:00", "scan_start", target="http://juice-shop:3000",
           model="openai/fixture", mode="graph", resumed=False,
           budget_turns=60, proxy=True, authenticated=True, scope_mode="full"),
        ev("10:00:01", "agent_start", objective="Orchestrate assessment",
           agent_ctx={"id": "a1", "name": "root", "role": "root"}),
        ev("10:00:05", "tool_call", turn=1, name="read_skill",
           args={"name": "coordination/root_agent"},
           agent_ctx={"id": "a1", "name": "root", "role": "root"}),
        ev("10:00:06", "tool_result", turn=1, name="read_skill",
           result="---\nname: coordination/root_agent\n---\n(playbook)"),
        ev("10:00:20", "assistant_text", turn=2, text="Decomposing the assessment.",
           agent_ctx={"id": "a1", "name": "root", "role": "root"}),
        ev("10:00:25", "tool_call", turn=2, name="create_agent",
           args={"name": "sqli-search", "objective": "Test SQL injection on search"},
           agent_ctx={"id": "a1", "name": "root", "role": "root"}),
        ev("10:00:26", "agent_created", agent_id="a2", agent="sqli-search",
           parent_id="a1", objective="Test SQL injection on search"),
        ev("10:00:30", "tool_call", turn=2, name="create_agent",
           args={"name": "client-side-xss", "objective": "XSS via browser"},
           agent_ctx={"id": "a1", "name": "root", "role": "root"}),
        ev("10:00:31", "agent_created", agent_id="a3", agent="client-side-xss",
           parent_id="a1", objective="XSS via browser"),
        ev("10:00:35", "agent_status", agent_id="a1", agent="root",
           from_="running", **{"from": "running", "to": "waiting",
                               "reason": "waiting for ['a2', 'a3']"}),
    ]
    sqli = {"id": "a2", "name": "sqli-search", "role": "specialist", "parent_id": "a1"}
    xss = {"id": "a3", "name": "client-side-xss", "role": "specialist", "parent_id": "a1"}
    events += [
        ev("10:00:40", "agent_start", objective="Test SQL injection on search",
           agent_ctx=sqli),
        ev("10:00:41", "tool_call", turn=1, name="read_skill",
           args={"name": "sql_injection"}, agent_ctx=sqli),
        ev("10:00:50", "tool_call", turn=2, name="exec_command",
           args={"command": "curl -s 'http://juice-shop:3000/rest/products/search?q=orange'"},
           agent_ctx=sqli),
        ev("10:00:51", "tool_result", turn=2, name="exec_command",
           result='{"exit_code": 0, "stdout": "[{\\"name\\":\\"Orange Juice\\"}]"}',
           agent_ctx=sqli),
        ev("10:01:10", "tool_call", turn=5, name="report_finding",
           args={"title": "Boolean-based blind SQL injection in product search",
                 "severity": "high", "cwe": "CWE-89",
                 "url": "http://juice-shop:3000/rest/products/search?q=x",
                 "description": "d", "evidence": "e", "poc": "p",
                 "remediation": "r", "confidence": "high"},
           agent_ctx=sqli),
        ev("10:01:20", "tool_call", turn=6, name="agent_finish",
           args={"status": "completed", "summary": "SQLi validated and filed."},
           agent_ctx=sqli),
        ev("10:01:21", "agent_end", stop_reason="agent_finish", turns_used=6,
           total_tokens=120000, findings=1, agent_ctx=sqli),
        ev("10:01:21", "agent_message", **{
            "from": "sqli-search", "to": "root", "to_id": "a1",
            "msg_type": "completion", "priority": "high",
            "preview": "COMPLETION REPORT: SQLi validated and filed."}),
        ev("10:01:22", "agent_status", agent_id="a2", agent="sqli-search",
           **{"from": "running", "to": "completed", "reason": "agent_finish"}),
        ev("10:01:22", "message_delivered", **{
            "from": "sqli-search", "msg_type": "completion",
            "preview": "COMPLETION REPORT: SQLi validated and filed.",
            "agent_ctx": {"id": "a1", "name": "root", "role": "root"}}),
    ]
    # browser specialist: navigate, screenshot, DOM-XSS finding
    events += [
        ev("10:00:41", "agent_start", objective="XSS via browser", agent_ctx=xss),
        ev("10:00:55", "tool_call", turn=1, name="browser_navigate",
           args={"url": "http://juice-shop:3000/"}, agent_ctx=xss),
        ev("10:01:00", "tool_call", turn=2, name="browser_evaluate",
           args={"expression": "location.hash = '#/search?q=<img src=x onerror=window.__xss=1>'"},
           agent_ctx=xss),
        ev("10:01:05", "screenshot", artifact="artifacts/client-side-xss/fixture-xss.png",
           bytes=20480, url="", agent_ctx=xss),
        ev("10:01:15", "tool_call", turn=4, name="report_finding",
           args={"title": "DOM-based XSS via search query", "severity": "high",
                 "cwe": "CWE-79", "url": "http://juice-shop:3000/#/search?q=",
                 "description": "d", "evidence": "window.__xss === 1", "poc": "p",
                 "remediation": "r", "confidence": "high"},
           agent_ctx=xss),
        ev("10:01:18", "tool_call", turn=5, name="agent_finish",
           args={"status": "completed", "summary": "DOM XSS executed via browser."},
           agent_ctx=xss),
        ev("10:01:19", "agent_end", stop_reason="agent_finish", turns_used=5,
           total_tokens=98000, findings=1, agent_ctx=xss),
        ev("10:01:19", "agent_status", agent_id="a3", agent="client-side-xss",
           **{"from": "running", "to": "completed", "reason": "agent_finish"}),
    ]
    # traffic: 30 captured flows + 1 scope block
    for i in range(1, 31):
        path = "/rest/products/search?q=x" if i % 3 else "/"
        events.append(ev(f"10:01:{i % 60:02d}", "proxy_flow", i=i, method="GET",
                         host="juice-shop", path=path, status=200))
    events += [
        ev("10:01:59", "scope_blocked", layer="proxy", host="api.pdtm.sh",
           method="CONNECT", reason="out of scope (CONNECT)"),
        ev("10:02:10", "agent_status", agent_id="a1", agent="root",
           **{"from": "waiting", "to": "running", "reason": "wait finished"}),
        ev("10:02:30", "tool_call", turn=3, name="finish_scan",
           args={"summary": "Two validated findings: blind SQLi + DOM XSS."},
           agent_ctx={"id": "a1", "name": "root", "role": "root"}),
        ev("10:02:31", "finish", summary="Two validated findings.",
           agent_ctx={"id": "a1", "name": "root", "role": "root"}),
        ev("10:02:31", "agent_end", stop_reason="finish_tool", turns_used=3,
           total_tokens=65000, findings=0,
           agent_ctx={"id": "a1", "name": "root", "role": "root"}),
        ev("10:02:31", "scan_end", stop_reason="finish_tool", turns_used=14,
           total_tokens=283000, findings=2),
    ]
    return events


FINDINGS = {
    "target": "http://juice-shop:3000",
    "started_at": "2026-08-16T10:00:00+00:00",
    "finished_at": "2026-08-16T10:02:31+00:00",
    "model": "openai/fixture",
    "summary": "Two validated findings: blind SQLi + DOM XSS.",
    "findings": [
        {"id": "VULN-001", "title": "Boolean-based blind SQL injection in product search",
         "severity": "high", "cwe": "CWE-89", "cvss_vector": None, "cvss_score": 7.5,
         "description": "User input concatenates into the SQLite query.",
         "evidence": "curl '.../search?q=orange%27%20AND%201=1--' → full list; AND 1=2 → empty",
         "poc": "curl -s 'http://juice-shop:3000/rest/products/search?q=orange%27+AND+1=1--'",
         "remediation": "Parameterize the query.", "confidence": "high",
         "url": "http://juice-shop:3000/rest/products/search?q=x", "reported_by": "sqli-search",
         "file": None, "line": None, "fix_patch": None},
        {"id": "VULN-002", "title": "DOM-based XSS via search query",
         "severity": "high", "cwe": "CWE-79", "cvss_vector": None, "cvss_score": 6.1,
         "description": "bypassSecurityTrustHtml sinks the fragment param.",
         "evidence": "browser_evaluate → window.__xss === 1; screenshot artifact",
         "poc": "Navigate to /#/search?q=<img src=x onerror=window.__xss=1>",
         "remediation": "Sanitize before insertion.", "confidence": "high",
         "url": "http://juice-shop:3000/#/search?q=", "reported_by": "client-side-xss",
         "file": None, "line": None, "fix_patch": None},
    ],
}


def main() -> None:
    FIXTURE.mkdir(parents=True, exist_ok=True)
    with open(FIXTURE / "transcript.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for event in build_transcript():
            fh.write(json.dumps(event) + "\n")
    (FIXTURE / "findings.json").write_text(
        json.dumps(FINDINGS, indent=2), encoding="utf-8", newline="\n")
    (FIXTURE / "config.json").write_text(json.dumps({
        "target": "http://juice-shop:3000", "model": "openai/fixture",
        "network": "vulnem-lab_labnet", "max_turns": 60, "scan_budget_turns": 60,
        "solo": False, "proxy": True, "creds": None, "ci": False, "fail_on": None,
        "scope_mode": "full", "source": None,
        "started_at": "2026-08-16T10:00:00+00:00", "vulnem_version": "0.1.0",
    }, indent=2), encoding="utf-8", newline="\n")
    (FIXTURE / "report.md").write_text(
        "# VulnEm Security Assessment Report\n\n(fixture)\n", encoding="utf-8",
        newline="\n")
    n = len(build_transcript())
    print(f"fixture written: {FIXTURE} ({n} events)")


if __name__ == "__main__":
    main()
