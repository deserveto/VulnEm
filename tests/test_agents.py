"""Coordinator + graph-tool tests with a scripted fake LLM and fake sandbox.

No Docker, no API key: the whole multi-agent machinery is exercised through
run_scan with completion_fn injected.
"""

import asyncio
import contextlib
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnem.agents.coordinator import TERMINAL_STATUSES, AgentStatus, Budget, Coordinator, Message
from vulnem.agents.session import HANDS_ON_SESSION_TOOLS
from vulnem.config import Settings
from vulnem.scan import _patch_dangling_tool_calls, run_scan
from vulnem.scope import Scope

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# -- fakes -------------------------------------------------------------------


class FakeSandbox:
    """Stand-in for the Docker sandbox: exec returns canned success."""

    class _Res:
        exit_code = 0
        stdout = "fake-output: HTTP/1.1 200 OK"
        stderr = ""
        duration = 0.01

    def __init__(self):
        self.put_files: list[tuple[bytes, str]] = []

    def exec(self, command: str, *, timeout: int = 120):
        return FakeSandbox._Res()

    def put_file(self, data: bytes, container_path: str) -> None:
        self.put_files.append((data, container_path))


def _response(text: str, tool: str | None, args: dict | None, idx: int):
    if tool is None:
        message = types.SimpleNamespace(content=text, tool_calls=None)
    else:
        tc = types.SimpleNamespace(
            id=f"call_{idx}",
            function=types.SimpleNamespace(name=tool, arguments=json.dumps(args or {})),
        )
        message = types.SimpleNamespace(content=text, tool_calls=[tc])
    usage = types.SimpleNamespace(prompt_tokens=10, completion_tokens=5)
    return types.SimpleNamespace(
        choices=[types.SimpleNamespace(message=message)], usage=usage
    )


class ScriptedLLM:
    """Routes scripted turns by agent, using the system-prompt role markers."""

    def __init__(self, scripts: dict[str, list[tuple]]):
        self.scripts = {k: list(v) for k, v in scripts.items()}
        self.calls: list[tuple[str, list[dict]]] = []
        self._i = 0

    def __call__(self, messages: list[dict], tools: list[dict]):
        system = next((m["content"] for m in messages if m.get("role") == "system"), "")
        key = None
        if "ROLE: ROOT ORCHESTRATOR" in system:
            key = "root"
        elif "ROLE: SPECIALIST (" in system:
            marker = system.split("ROLE: SPECIALIST (", 1)[1]
            name = marker.split(")", 1)[0]
            key = name
        elif "ROLE: SOLO" in system:
            key = "solo"
        if key is None or key not in self.scripts:
            raise AssertionError(f"scripted LLM cannot route session (key={key!r})")
        self.calls.append((key, messages))
        queue = self.scripts[key]
        if not queue:
            raise AssertionError(f"script for {key!r} exhausted")
        text, tool, args = queue.pop(0)
        self._i += 1
        return _response(text, tool, args, self._i)


def make_settings(**overrides) -> Settings:
    kwargs = dict(
        model="fake/model",
        max_turns=12,
        child_max_turns=8,
        max_agents=6,
        max_total_tokens=1_000_000,
        skills_dir=PROJECT_ROOT / "skills",
    )
    kwargs.update(overrides)
    s = Settings(**kwargs)
    return s


# -- Budget --------------------------------------------------------------------


def test_budget_turns_and_extend():
    b = Budget(max_turns=2)
    assert b.charge_turn() and b.turns_used == 1
    assert b.charge_turn() is False  # second charge hits the cap
    assert b.exhausted
    b.extend(max_turns=4)
    assert not b.exhausted
    assert b.charge_turn()


def test_budget_tokens():
    b = Budget(max_tokens=100)
    assert b.charge_tokens(60)
    assert b.charge_tokens(60) is False
    assert b.exhausted


def test_budget_roundtrip():
    b = Budget(max_turns=10, max_tokens=5000)
    b.charge_turn()
    b.charge_tokens(123)
    restored = Budget.from_dict(b.to_dict())
    assert (restored.max_turns, restored.max_tokens,
            restored.turns_used, restored.tokens_used) == (10, 5000, 1, 123)


# -- registry ------------------------------------------------------------------


def test_register_enforces_unique_names_and_cap(tmp_path):
    c = Coordinator(run_dir=tmp_path, max_agents=2)
    c.register(name="alpha", role="root", parent_id=None, objective="o", max_turns=5)
    with pytest.raises(ValueError):
        c.register(name="alpha", role="specialist", parent_id="a1", objective="o", max_turns=5)
    c.register(name="beta", role="specialist", parent_id="a1", objective="o", max_turns=5)
    with pytest.raises(ValueError):
        c.register(name="gamma", role="specialist", parent_id="a1", objective="o", max_turns=5)
    assert c.resolve("beta").name == "beta"
    assert c.resolve("a2").name == "beta"
    assert [a.name for a in c.children_of("a1")] == ["beta"]


# -- mailboxes -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mailbox_deliver_and_drain(tmp_path):
    c = Coordinator(run_dir=tmp_path)
    rec = c.register(name="alpha", role="root", parent_id=None, objective="o", max_turns=5)
    assert c.drain_mailbox(rec) == []
    assert await c.deliver(rec, Message(from_name="x", msg_type="info",
                                        priority="normal", content="hello"))
    assert rec.wake_event.is_set()
    msgs = c.drain_mailbox(rec)
    assert len(msgs) == 1 and msgs[0].content == "hello"
    assert msgs[0].render().startswith("[Message from x | info | normal]")
    assert not rec.wake_event.is_set()
    # terminal agents refuse mail
    c.set_status(rec, AgentStatus.COMPLETED)
    assert not await c.deliver(rec, Message(from_name="x", msg_type="info",
                                            priority="normal", content="late"))


# -- wait_for --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wait_for_parks_until_terminal(tmp_path):
    c = Coordinator(run_dir=tmp_path)
    root = c.register(name="root", role="root", parent_id=None, objective="o", max_turns=5)
    child = c.register(name="kid", role="specialist", parent_id="a1", objective="o", max_turns=5)

    async def finish_later():
        await asyncio.sleep(0.02)
        c.set_status(child, AgentStatus.COMPLETED)

    asyncio.get_running_loop().create_task(finish_later())
    result = await asyncio.wait_for(c.wait_for(root, [child.agent_id]), timeout=2)
    assert result["woken_by"] == "all_done"
    assert result["agents"][0]["status"] == "completed"
    assert root.status == AgentStatus.RUNNING  # un-parked


@pytest.mark.asyncio
async def test_wait_for_revived_by_message(tmp_path):
    c = Coordinator(run_dir=tmp_path)
    root = c.register(name="root", role="root", parent_id=None, objective="o", max_turns=5)
    child = c.register(name="kid", role="specialist", parent_id="a1", objective="o", max_turns=5)

    async def ping_later():
        await asyncio.sleep(0.02)
        await c.deliver(root, Message(from_name="kid", msg_type="alert",
                                      priority="high", content="found something"))

    asyncio.get_running_loop().create_task(ping_later())
    result = await asyncio.wait_for(c.wait_for(root, [child.agent_id], timeout_s=5), timeout=2)
    assert result["woken_by"] == "message"
    assert root.status == AgentStatus.RUNNING


@pytest.mark.asyncio
async def test_wait_for_timeout(tmp_path):
    c = Coordinator(run_dir=tmp_path)
    root = c.register(name="root", role="root", parent_id=None, objective="o", max_turns=5)
    child = c.register(name="kid", role="specialist", parent_id="a1", objective="o", max_turns=5)
    result = await c.wait_for(root, [child.agent_id], timeout_s=0.05)
    assert result["woken_by"] == "timeout"
    assert result["still_running"] == ["kid"]
    assert root.status == AgentStatus.RUNNING


@pytest.mark.asyncio
async def test_stop_agent_marks_and_notifies_parent(tmp_path):
    c = Coordinator(run_dir=tmp_path)
    root = c.register(name="root", role="root", parent_id=None, objective="o", max_turns=5)
    child = c.register(name="kid", role="specialist", parent_id="a1", objective="o", max_turns=5)

    async def forever():
        await asyncio.sleep(100)

    child.task = asyncio.get_running_loop().create_task(forever())
    await c.stop_agent(child, "burning budget")
    assert child.status == AgentStatus.STOPPED and child.terminal
    assert child.done_event.is_set()
    msgs = c.drain_mailbox(root)
    assert len(msgs) == 1 and "was stopped" in msgs[0].content
    with pytest.raises(asyncio.CancelledError):
        await child.task


# -- full graph flow ---------------------------------------------------------------


ROOT_SCRIPT = [
    ("", "think", {"thoughts": "decompose the assessment"}),
    ("", "read_skill", {"name": "coordination/root_agent"}),
    ("", "create_agent", {"name": "sqli-probe",
                          "objective": "Test SQLi on the search API of {TARGET}. "
                                       "Read sql_injection first. ~6 turns."}),
    ("", "create_agent", {"name": "xss-probe",
                          "objective": "Test XSS on the search page of {TARGET}. "
                                       "Read xss first. ~5 turns."}),
    # Each completion-report message wakes a parked waiter early; the scripted
    # root stands in for a real root reacting to wait results by waiting
    # again until every child is terminal.
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "wait_for_agents", {}),
    ("", "view_agent_graph", {}),
    ("", "report_coverage", {"rows": [
        {"area": "injection", "surface": "search API inputs",
         "status": "tested_findings", "agent": "sqli-probe"},
        {"area": "client-side", "surface": "search page reflection",
         "status": "tested_findings", "agent": "xss-probe"},
    ]}),
    ("Scan complete.", "finish_scan", {"summary": "Two specialists completed; "
                                                  "one merged finding."}),
]

SQLI_SCRIPT = [
    ("", "read_skill", {"name": "sql_injection"}),
    ("", "exec_command", {"command": "curl -s '{TARGET}/rest/products/search?q='"}),
    ("", "report_finding", {
        "title": "SQL injection in product search",
        "severity": "high",
        "cwe": "CWE-89",
        "url": "{TARGET}/rest/products/search?q=x",  # overlap with xss agent
        "description": "Boolean-based SQLi in q parameter.",
        "evidence": "1=1 vs 1=2 length diff",
        "poc": "curl '.../search?q=pet' AND 1=2-- -",
        "remediation": "Parameterized queries.",
    }),
    ("", "agent_finish", {"status": "completed", "summary": "SQLi validated.",
                          "recommendations": "Test other params later."}),
]

XSS_SCRIPT = [
    ("", "read_skill", {"name": "xss"}),
    ("", "exec_command", {"command": "curl -s '{TARGET}/search?q=<script>'"}),
    ("", "report_finding", {
        "title": "Reflected XSS in search",  # different class → separate finding
        "severity": "medium",
        "cwe": "CWE-79",
        "url": "{TARGET}/search?q=y",
        "description": "Reflected input in result page.",
        "evidence": "script tag echoed",
        "poc": "curl '.../search?q=<script>'",
        "remediation": "Escape output.",
    }),
    ("", "report_finding", {
        "title": "Injection in search API",  # same endpoint+class as SQLi → dedupes
        "severity": "high",
        "cwe": "CWE-89",
        "url": "{TARGET}/rest/products/search?q=z",
        "description": "Duplicate detection from another agent.",
        "evidence": "sqlmap banner: is vulnerable",
        "poc": "sqlmap -u ...",
        "remediation": "Parameterized queries.",
    }),
    ("", "agent_finish", {"status": "completed", "summary": "XSS validated; "
                                                            "overlap reported."}),
]


def _substitute(script, target: str):
    out = []
    for text, tool, args in script:
        args = json.loads(json.dumps(args).replace("{TARGET}", target))
        out.append((text, tool, args))
    return out


@pytest.mark.asyncio
async def test_full_graph_flow(tmp_path):
    scope = Scope.from_target("http://juice-shop:3000")
    llm = ScriptedLLM({
        "root": _substitute(ROOT_SCRIPT, scope.target_url),
        "sqli-probe": _substitute(SQLI_SCRIPT, scope.target_url),
        "xss-probe": _substitute(XSS_SCRIPT, scope.target_url),
    })
    result = await run_scan(
        scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
        run_dir=tmp_path, completion_fn=llm,
    )

    assert result.finished and result.stop_reason == "finish_tool"
    # two findings after cross-agent dedupe (search-API overlap merged)
    assert len(result.findings) == 2
    merged = next(f for f in result.findings if f.cwe == "CWE-89")
    assert "sqli-probe" in merged.reported_by and "xss-probe" in merged.reported_by
    assert "also reported by" in merged.evidence
    assert merged.severity == "high"
    assert [f.id for f in result.findings] == ["VULN-001", "VULN-002"]

    # snapshot artifacts exist
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    names = {a["name"]: a for a in state["agents"]}
    assert set(names) == {"root", "sqli-probe", "xss-probe"}
    assert names["sqli-probe"]["status"] == "completed"
    assert names["sqli-probe"]["completion_report"]["status"] == "completed"
    assert len(names["sqli-probe"]["completion_report"]["findings"]) == 1
    assert (tmp_path / "sessions" / "a2.json").is_file()

    # transcript: attribution + graph events
    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    kinds = {e["type"] for e in events}
    assert {"agent_created", "agent_status", "agent_message", "tool_call",
            "message_delivered", "scan_end"} <= kinds
    attributed = [e for e in events if e["type"] == "tool_call" and
                  e.get("agent_ctx", {}).get("name") == "sqli-probe"]
    assert attributed, "tool_call events must carry agent attribution"
    statuses = [(e["from"], e["to"]) for e in events if e["type"] == "agent_status"]
    assert ("running", "waiting") in statuses  # root parked in wait_for_agents
    assert any(to == "completed" for _, to in statuses)

    # root received both completion reports as messages
    root_msgs = [e for e in events if e["type"] == "message_delivered"
                 and e["from"] in {"sqli-probe", "xss-probe"}]
    assert len(root_msgs) == 2


@pytest.mark.asyncio
async def test_graph_budget_force_stops_neverending_agents(tmp_path):
    scope = Scope.from_target("http://t:80")
    loop_script = [("", "exec_command", {"command": "curl -s http://t"})] * 50
    llm = ScriptedLLM({
        "root": [("", "create_agent", {"name": "runner",
                                       "objective": "probe forever"})]
                 + [("", "wait_for_agents", {"timeout_s": 30})] * 10
                 + [("", "finish_scan", {"summary": "done"})],
        "runner": loop_script,
    })
    result = await run_scan(
        scope=scope, settings=make_settings(child_max_turns=3), sandbox=FakeSandbox(),
        run_dir=tmp_path, completion_fn=llm, budget_turns=10,
    )
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    runner = next(a for a in state["agents"] if a["name"] == "runner")
    # runner hit its per-agent cap (3) before the scan-wide cap mattered
    assert runner["status"] == "failed"
    assert runner["stop_reason"] == "max_turns"
    # root burned its wrap-up grace without finishing → force-stopped by budget
    root = next(a for a in state["agents"] if a["name"] == "root")
    assert root["status"] == "stopped"
    assert root["stop_reason"] == "scan_budget"
    assert result.stop_reason == "scan_budget"
    assert result.turns_used >= 4  # grace turns allowed over the cap


@pytest.mark.asyncio
async def test_child_failure_isolated_and_parent_alerted(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        "root": [("", "create_agent", {"name": "doomed",
                                       "objective": "will fail"}),
                 ("", "wait_for_agents", {}),
                 ("", "report_coverage", {"rows": [
                     {"area": "auth flows", "surface": "none attempted",
                      "status": "skipped", "note": "child stalled early"}]}),
                 ("", "finish_scan", {"summary": "child failed but scan continued"})],
        # doomed: text-only turns → stall → FAILED
        "doomed": [("just thinking...", None, None)] * 10,
    })
    result = await run_scan(
        scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
        run_dir=tmp_path, completion_fn=llm,
    )
    assert result.finished
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    doomed = next(a for a in state["agents"] if a["name"] == "doomed")
    assert doomed["status"] == "failed"
    assert doomed["stop_reason"] == "stalled"
    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    alerts = [e for e in events if e["type"] == "message_delivered" and e["from"] == "doomed"]
    assert alerts, "parent must be alerted when a child fails"


@pytest.mark.asyncio
async def test_agent_finish_rejects_bad_status(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        "root": [("", "create_agent", {"name": "kid", "objective": "o"}),
                 ("", "wait_for_agents", {}),
                 ("", "report_coverage", {"rows": [
                     {"area": "auth flows", "surface": "login",
                      "status": "tested_clean", "agent": "kid"}]}),
                 ("", "finish_scan", {"summary": "s"})],
        "kid": [("", "agent_finish", {"status": "banana", "summary": "?"}),  # rejected
                ("", "agent_finish", {"status": "failed", "summary": "blocked by waf"})],
    })
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, completion_fn=llm)
    assert result.finished
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    kid = next(a for a in state["agents"] if a["name"] == "kid")
    assert kid["status"] == "failed"  # report status failed → FAILED lifecycle
    assert kid["completion_report"]["status"] == "failed"


@pytest.mark.asyncio
async def test_solo_mode_still_works(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        "solo": [("", "think", {"thoughts": "plan"}),
                 ("", "exec_command", {"command": "curl -s http://t"}),
                 ("", "report_finding", {
                     "title": "Solo finding", "severity": "low",
                     "description": "d", "evidence": "e", "poc": "p",
                     "remediation": "r", "url": "http://t/x"}),
                 ("Done.", "finish_scan", {"summary": "solo scan complete"})],
    })
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, solo=True, completion_fn=llm)
    assert result.finished and result.stop_reason == "finish_tool"
    assert len(result.findings) == 1 and result.findings[0].reported_by == "solo"
    assert result.findings[0].id == "VULN-001"


# -- Phase 3 tool surface -----------------------------------------------------------


def test_specialists_get_browser_and_proxy_tools():
    from vulnem.agent.tools import SCHEMA_BY_NAME
    from vulnem.scan import SOLO_TOOLS

    for name in ("browser_navigate", "browser_click", "browser_fill",
                 "browser_read_page", "browser_evaluate", "browser_screenshot",
                 "list_requests", "view_request", "repeat_request", "view_sitemap"):
        assert name in HANDS_ON_SESSION_TOOLS, f"{name} missing from hands-on toolset"
        assert name in SCHEMA_BY_NAME, f"{name} missing schema"
        assert name in SOLO_TOOLS, f"{name} missing from solo toolset"
    # root stays delegation-only: no exec/browser/proxy hands-on tools
    from vulnem.scan import ROOT_TOOLS

    assert not (ROOT_TOOLS & {"exec_command", "browser_navigate", "list_requests"})


# -- restore helpers --------------------------------------------------------------


@pytest.mark.asyncio
async def test_resume_after_interrupt(tmp_path):
    # 1. complete a graph run, then simulate a crash mid-run: root flipped
    # back to waiting with a dangling wait_for_agents tool call.
    scope = Scope.from_target("http://juice-shop:3000")
    llm = ScriptedLLM({
        "root": _substitute(ROOT_SCRIPT, scope.target_url),
        "sqli-probe": _substitute(SQLI_SCRIPT, scope.target_url),
        "xss-probe": _substitute(XSS_SCRIPT, scope.target_url),
    })
    # ROOT_SCRIPT grew a report_coverage turn — leave the resumed root room
    # for its wrap-up turns within the per-agent cap
    await run_scan(scope=scope, settings=make_settings(max_turns=16),
                   sandbox=FakeSandbox(), run_dir=tmp_path, completion_fn=llm)

    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    root_entry = next(a for a in state["agents"] if a["name"] == "root")
    root_entry["status"] = "waiting"
    root_entry["stop_reason"] = ""
    root_entry["completion_report"] = None
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")

    sess_path = tmp_path / "sessions" / "a1.json"
    sess = json.loads(sess_path.read_text(encoding="utf-8"))
    sess["messages"].append({
        "role": "assistant", "content": "",
        "tool_calls": [{"id": "dangling1", "type": "function",
                        "function": {"name": "wait_for_agents", "arguments": "{}"}}],
    })
    sess_path.write_text(json.dumps(sess), encoding="utf-8")

    # 2. resume: root wraps up; children stay completed with findings intact
    llm2 = ScriptedLLM({"root": [
        ("", "view_agent_graph", {}),
        ("Resumed and done.", "finish_scan", {"summary": "resumed summary"}),
    ]})
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, resume_state=state, completion_fn=llm2)

    assert result.finished and result.stop_reason == "finish_tool"
    assert result.summary == "resumed summary"
    assert len(result.findings) == 2  # children's findings survived the resume
    merged = next(f for f in result.findings if f.cwe == "CWE-89")
    assert "sqli-probe" in merged.reported_by and "xss-probe" in merged.reported_by

    sess2 = json.loads(sess_path.read_text(encoding="utf-8"))
    dangling = [m for m in sess2["messages"]
                if m.get("role") == "tool" and m.get("tool_call_id") == "dangling1"]
    assert dangling and "interrupted" in dangling[0]["content"]
    resumed = [m for m in sess2["messages"]
               if m.get("role") == "user" and "RESUMED" in str(m.get("content"))]
    assert resumed, "resumed agents must be told the scan was resumed"


def test_load_resume_state_rejects_finished_runs(tmp_path):
    from vulnem.scan import load_resume_state

    (tmp_path / "config.json").write_text('{"target": "http://t:80"}', encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        load_resume_state(tmp_path)
    (tmp_path / "state.json").write_text(json.dumps({
        "budget": {}, "agents": [
            {"agent_id": "a1", "name": "root", "role": "root", "status": "completed"},
        ],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="already finished"):
        load_resume_state(tmp_path)


@pytest.mark.asyncio
async def test_real_interrupt_leaves_run_resumable(tmp_path):
    """A genuine mid-scan CancelledError (what Ctrl+C delivers through
    asyncio.run) must snapshot root/waiting and leave it NON-terminal so the
    run stays resumable — regression: the session cancel-handler used to
    finalize interrupted agents as STOPPED (terminal), which made
    `vulnem resume` refuse the run and fabricated salvage reports."""
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        # root parks on the 2nd wait: fast-kid woke it once, sleeper is still
        # mid-exec, so there is nothing left to wake it again.
        "root": [("", "create_agent", {"name": "fast-kid", "objective": "probe"}),
                 ("", "create_agent", {"name": "sleeper", "objective": "slow probe"}),
                 ("", "wait_for_agents", {}),
                 ("", "wait_for_agents", {}),
                 # consumed after the resume (wait #3 is woken by sleeper)
                 ("", "wait_for_agents", {}),
                 ("", "view_agent_graph", {}),
                 ("", "report_coverage", {"rows": [
                     {"area": "auth flows", "surface": "probes",
                      "status": "tested_clean"}]}),
                 ("Resumed.", "finish_scan", {"summary": "resumed done"})],
        "fast-kid": [("", "exec_command", {"command": "curl fast-probe"}),
                     ("Done.", "agent_finish", {"status": "completed", "summary": "f"})],
        "sleeper": [("", "exec_command", {"command": "curl slow-probe"}),
                    ("Done.", "agent_finish", {"status": "completed", "summary": "s"})],
    })

    class SlowFakeSandbox(FakeSandbox):
        """Execs block just long enough that root parks BEFORE each child
        ends — completion reports then arrive while root is parked (the
        wake pattern real scans produce), and the sleeper keeps root's
        second wait parked until the cancel."""

        def exec(self, command: str, *, timeout: int = 120):
            import time

            if "slow-probe" in command:
                time.sleep(3.0)
            elif "fast-probe" in command:
                time.sleep(0.3)
            return FakeSandbox._Res()

    events: list[dict] = []
    task = asyncio.create_task(run_scan(
        scope=scope, settings=make_settings(), sandbox=SlowFakeSandbox(),
        run_dir=tmp_path, completion_fn=llm, on_event=events.append))
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 15
    while loop.time() < deadline:
        parks = sum(1 for e in events if e.get("type") == "agent_status"
                    and e.get("agent") == "root" and e.get("to") == "waiting")
        fast_done = any(e.get("type") == "agent_status" and e.get("agent") == "fast-kid"
                        and e.get("to") == "completed" for e in events)
        sleeper_mid = any(e.get("type") == "tool_call" and e.get("name") == "exec_command"
                          and "slow-probe" in str((e.get("args") or {}).get("command", ""))
                          and (e.get("agent_ctx") or {}).get("name") == "sleeper"
                          for e in events)
        if parks >= 2 and fast_done and sleeper_mid:
            break
        await asyncio.sleep(0.02)
    else:
        raise AssertionError("interrupt condition never reached")
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    agents = {a["name"]: a for a in state["agents"]}
    # wait_for's finally may flip root waiting→running while the cancel
    # unwinds; either way it must be NON-terminal for resume to continue it
    assert agents["root"]["status"] in {"waiting", "running"}  # NOT stopped
    assert agents["fast-kid"]["status"] == "completed"
    assert agents["sleeper"]["status"] == "running"  # mid-work, not finalized
    assert agents["root"].get("completion_report") is None  # no fake salvage
    from vulnem.scan import load_resume_state

    (tmp_path / "config.json").write_text(
        json.dumps({"target": "http://t:80", "network": None, "proxy": False,
                    "solo": False}), encoding="utf-8")
    state = load_resume_state(tmp_path)  # must NOT refuse the run

    result = await run_scan(scope=scope, settings=make_settings(),
                            sandbox=SlowFakeSandbox(), run_dir=tmp_path,
                            resume_state=state, completion_fn=llm)
    assert result.finished and result.stop_reason == "finish_tool"
    assert result.summary == "resumed done"
    state2 = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    final = {a["name"]: a for a in state2["agents"]}
    assert final["root"]["status"] == "completed"
    assert final["fast-kid"]["status"] == "completed"  # terminal survived resume
    assert final["sleeper"]["status"] == "completed"  # continued after resume


def test_patch_dangling_tool_calls():
    messages = [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "exec_command", "arguments": "{}"}},
            {"id": "c2", "type": "function",
             "function": {"name": "think", "arguments": "{}"}},
        ]},
        {"role": "tool", "tool_call_id": "c1", "content": "ok"},
        # c2 never answered — crash happened here
    ]
    _patch_dangling_tool_calls(messages)
    patched = [m for m in messages if m.get("role") == "tool" and m["tool_call_id"] == "c2"]
    assert len(patched) == 1
    assert "interrupted" in patched[0]["content"]


def test_patch_leaves_complete_conversations_alone():
    messages = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "think", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "ok"},
    ]
    before = json.dumps(messages)
    _patch_dangling_tool_calls(messages)
    assert json.dumps(messages) == before


def test_terminal_statuses_are_final(tmp_path):
    c = Coordinator(run_dir=tmp_path)
    rec = c.register(name="a", role="root", parent_id=None, objective="o", max_turns=5)
    c.set_status(rec, AgentStatus.COMPLETED)
    c.set_status(rec, AgentStatus.RUNNING)  # ignored
    assert rec.status == AgentStatus.COMPLETED
    assert rec.status in TERMINAL_STATUSES


# -- salvage of unfinished specialists ---------------------------------------------


@pytest.mark.asyncio
async def test_capped_specialist_gets_salvaged_completion_report(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        "root": [("", "create_agent", {"name": "mapper",
                                       "objective": "map the API"}),
                 ("", "wait_for_agents", {}),
                 ("", "report_coverage", {"rows": [
                     {"area": "access control", "surface": "API mapping",
                      "status": "partial", "note": "mapper hit its cap"}]}),
                 ("", "finish_scan", {"summary": "collected salvaged report"})],
        # mapper works (prose + tool calls + a finding) but never calls
        # agent_finish → hits its per-agent cap (child_max_turns=3)
        "mapper": [
            ("Mapped /api/products and /api/users; auth flow next.",
             "exec_command", {"command": "curl -s http://t/api/products"}),
            ("Auth is a JWT in a cookie; basket endpoint looks like IDOR.",
             "report_finding", {
                 "title": "IDOR lead in basket API", "severity": "medium",
                 "cwe": "CWE-639", "url": "http://t/api/basket",
                 "description": "d", "evidence": "e", "poc": "p", "remediation": "r"}),
            ("Lead filed; /api/basket/merge is unvalidated too — next target.",
             "exec_command", {"command": "curl -s http://t/api/basket"}),
        ],
    })
    result = await run_scan(scope=scope, settings=make_settings(child_max_turns=3),
                            sandbox=FakeSandbox(), run_dir=tmp_path, completion_fn=llm)
    assert result.finished

    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    mapper = next(a for a in state["agents"] if a["name"] == "mapper")
    assert mapper["status"] == "failed"
    assert mapper["stop_reason"] == "max_turns"
    report = mapper["completion_report"]
    assert report is not None and report["agent"] == "mapper"
    assert report["status"] == "failed"
    assert report["recommendations"] == ""
    assert "AUTO-SALVAGED" in report["summary"]
    assert "turn cap" in report["summary"]
    assert "Turns used: 3/3" in report["summary"]
    # the agent's last assistant text is the payload that must survive
    assert "/api/basket/merge is unvalidated" in report["summary"]
    assert [f["title"] for f in report["findings"]] == ["IDOR lead in basket API"]
    assert set(report["findings"][0]) == {"id", "title", "severity", "url", "cwe"}

    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    to_root = [e for e in events if e["type"] == "agent_message" and e["to"] == "root"]
    reports = [e for e in to_root if e["msg_type"] == "completion_report"]
    assert len(reports) == 1 and reports[0]["from"] == "mapper"
    assert "AUTO-SALVAGED" in reports[0]["preview"]
    # the salvaged report replaces the generic failure alert — not both
    assert not [e for e in to_root if e["msg_type"] == "alert"]
    end = next(e for e in events if e["type"] == "agent_end"
               and e["agent_ctx"]["name"] == "mapper")
    assert end["salvaged"] is True


@pytest.mark.asyncio
async def test_budget_stopped_specialist_also_salvaged(tmp_path):
    # Driven directly (not via run_scan) so the scan budget is exactly
    # exhausted before the specialist starts: it gets its 2 wrap-up grace
    # turns, is force-stopped with stop_reason scan_budget, and the salvage
    # must still hand the parent a structured report (lifecycle stays STOPPED).
    from vulnem.agents.session import AgentSession, run_agent

    coordinator = Coordinator(run_dir=tmp_path, budget=Budget(max_turns=2))
    coordinator.register(name="root", role="root", parent_id=None,
                         objective="o", max_turns=10)
    kid = coordinator.register(name="slowpoke", role="specialist", parent_id="a1",
                               objective="probe", max_turns=50)
    calls = {"n": 0}

    def completion_fn(messages, tools):
        calls["n"] += 1
        return _response("found an unvalidated redirect on /login", "exec_command",
                         {"command": "curl -s http://t/login"}, calls["n"])

    session = AgentSession(
        record=kid, coordinator=coordinator, scope=Scope.from_target("http://t:80"),
        settings=make_settings(), sandbox=FakeSandbox(),
        tool_names={"exec_command"}, finish_tool="agent_finish",
        system_prompt="ROLE: SPECIALIST (slowpoke)", initial_task="probe",
        completion_fn=completion_fn,
    )
    coordinator.budget.charge_turn()
    coordinator.budget.charge_turn()  # scan budget exhausted before the agent runs
    outcome = await run_agent(session)

    assert outcome.stop_reason == "scan_budget" and not outcome.finished
    assert kid.status == AgentStatus.STOPPED
    report = kid.completion_report
    assert report is not None and report["status"] == "failed"
    assert "AUTO-SALVAGED" in report["summary"]
    assert "scan-wide budget" in report["summary"]
    assert "unvalidated redirect" in report["summary"]  # last assistant text kept
    assert report["findings"] == []
    msgs = coordinator.drain_mailbox(coordinator.agents["a1"])
    assert [m.msg_type for m in msgs] == ["completion_report"]  # report, not an alert
    assert msgs[0].priority == "high"
    assert msgs[0].content.startswith("COMPLETION REPORT from specialist 'slowpoke'")
    assert "AUTO-SALVAGED" in msgs[0].content
    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    end = next(e for e in events if e["type"] == "agent_end"
               and e["agent_ctx"]["name"] == "slowpoke")
    assert end["salvaged"] is True


@pytest.mark.asyncio
async def test_salvage_does_not_overwrite_deliberate_finish(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        "root": [("", "create_agent", {"name": "kid", "objective": "o"}),
                 ("", "wait_for_agents", {}),
                 ("", "report_coverage", {"rows": [
                     {"area": "auth flows", "surface": "login",
                      "status": "tested_clean", "agent": "kid"}]}),
                 ("", "finish_scan", {"summary": "s"})],
        "kid": [("halfway there", "exec_command", {"command": "curl -s http://t"}),
                ("", "agent_finish", {"status": "completed", "summary": "did the thing",
                                      "recommendations": "retry with deeper auth"})],
    })
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, completion_fn=llm)
    assert result.finished
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    kid = next(a for a in state["agents"] if a["name"] == "kid")
    assert kid["status"] == "completed"
    assert kid["completion_report"]["summary"] == "did the thing"
    assert kid["completion_report"]["recommendations"] == "retry with deeper auth"
    assert "AUTO-SALVAGED" not in kid["completion_report"]["summary"]
    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    end = next(e for e in events if e["type"] == "agent_end"
               and e["agent_ctx"]["name"] == "kid")
    assert "salvaged" not in end


@pytest.mark.asyncio
async def test_root_force_stopped_gets_no_salvage(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({"root": [("", "think", {"thoughts": "planning"})] * 20})
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, completion_fn=llm, budget_turns=1)
    assert not result.finished and result.stop_reason == "scan_budget"
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    root = next(a for a in state["agents"] if a["name"] == "root")
    assert root["status"] == "stopped"
    assert root["completion_report"] is None  # no parent → nothing to salvage for
    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    assert not [e for e in events if e["type"] == "agent_message"]
    end = next(e for e in events if e["type"] == "agent_end")
    assert "salvaged" not in end


@pytest.mark.asyncio
async def test_stalled_specialist_salvage_falls_back_to_outcome_summary(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        "root": [("", "create_agent", {"name": "daydreamer", "objective": "o"}),
                 ("", "wait_for_agents", {}),
                 ("", "report_coverage", {"rows": [
                     {"area": "auth flows", "surface": "none",
                      "status": "skipped", "note": "specialist stalled"}]}),
                 ("", "finish_scan", {"summary": "s"})],
        # text-only turns → stall; no assistant message ever reaches the session
        "daydreamer": [("just thinking...", None, None)] * 10,
    })
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, completion_fn=llm)
    assert result.finished
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    kid = next(a for a in state["agents"] if a["name"] == "daydreamer")
    assert kid["status"] == "failed"
    report = kid["completion_report"]
    assert report is not None and "AUTO-SALVAGED" in report["summary"]
    # no assistant text was ever recorded → the outcome line stands in
    assert "without calling any tool" in report["summary"]
    assert report["findings"] == []
    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    to_root = [e for e in events if e["type"] == "agent_message" and e["to"] == "root"]
    assert [e["msg_type"] for e in to_root] == ["completion_report"]


@pytest.mark.asyncio
async def test_finish_scan_sweep_salvages_live_specialists(tmp_path):
    # Root finishing the scan stops still-live specialists via the finish_scan
    # sweep, which terminalizes records BEFORE cancelling their tasks — so
    # finalize_agent's terminal guard skips them. The sweep itself must file
    # the salvage (report + agent_end + parent message) or a mid-work
    # specialist's narrative vanishes (observed live: 976k tokens lost).
    from vulnem.agents.graph_tools import _tool_finish_scan, _tool_report_coverage
    from vulnem.agents.session import AgentSession

    coordinator = Coordinator(run_dir=tmp_path, budget=Budget(max_turns=100))
    root = coordinator.register(name="root", role="root", parent_id=None,
                                objective="o", max_turns=10)
    kid = coordinator.register(name="mapper", role="specialist", parent_id="a1",
                               objective="map the API", max_turns=30)
    scope = Scope.from_target("http://t:80")

    def _session(record, finish):
        return AgentSession(
            record=record, coordinator=coordinator, scope=scope,
            settings=make_settings(), sandbox=FakeSandbox(),
            tool_names={"exec_command"}, finish_tool=finish,
            system_prompt="SP", initial_task="t", completion_fn=None,
        )

    root_session = _session(root, "finish_scan")
    kid_session = _session(kid, "agent_finish")
    kid.turns_used = 5
    kid_session.messages.append(
        {"role": "assistant", "content": "Mapped 12 API routes; session flow next."})

    # root files coverage first — otherwise finish_scan bounces once
    cov = await _tool_report_coverage(root_session, {"rows": [
        {"area": "access control", "surface": "API routes", "status": "partial",
         "note": "scan ending mid-mission"}]})
    assert json.loads(cov)["ok"] is True
    result = await _tool_finish_scan(root_session, {"summary": "scan done"})

    assert json.loads(result)["ok"] is True
    assert kid.status == AgentStatus.STOPPED
    assert kid.stop_reason == "scan finished by root"
    report = kid.completion_report
    assert report is not None and report["agent"] == "mapper"
    assert "AUTO-SALVAGED" in report["summary"]
    assert "finished the scan" in report["summary"]
    assert "Turns used: 5/30" in report["summary"]
    assert "Mapped 12 API routes" in report["summary"]  # last progress kept
    assert root.completion_report == {"status": "completed", "summary": "scan done"}

    msgs = coordinator.drain_mailbox(root)
    assert [m.msg_type for m in msgs] == ["completion_report"]
    assert msgs[0].content.startswith("COMPLETION REPORT from specialist 'mapper'")

    events = [json.loads(line) for line in
              (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
    ends = [e for e in events if e["type"] == "agent_end"
            and e["agent_ctx"]["name"] == "mapper"]
    assert len(ends) == 1
    assert ends[0]["salvaged"] is True
    assert ends[0]["stop_reason"] == "scan finished by root"


@pytest.mark.asyncio
async def test_only_engine_errors_skip_salvage(tmp_path):
    # finalize_agent salvages by DENYLIST: every stop reason except "error"
    # keeps its narrative — including custom reasons future tools may invent.
    from vulnem.agents.session import AgentOutcome, AgentSession, finalize_agent

    async def _finalize(stop_reason: str):
        run_dir = tmp_path / stop_reason.replace(" ", "-")
        run_dir.mkdir()
        coordinator = Coordinator(run_dir=run_dir, budget=Budget(max_turns=100))
        coordinator.register(name="root", role="root", parent_id=None,
                             objective="o", max_turns=10)
        kid = coordinator.register(name="worker", role="specialist", parent_id="a1",
                                   objective="o", max_turns=10)
        session = AgentSession(
            record=kid, coordinator=coordinator, scope=Scope.from_target("http://t:80"),
            settings=make_settings(), sandbox=FakeSandbox(),
            tool_names={"exec_command"}, finish_tool="agent_finish",
            system_prompt="SP", initial_task="t", completion_fn=None,
        )
        session.messages.append({"role": "assistant", "content": "progress note"})
        await finalize_agent(session, AgentOutcome(stop_reason=stop_reason,
                                                   summary="s", finished=False))
        return coordinator, kid

    coordinator, kid = await _finalize("error")
    assert kid.completion_report is None  # engine errors keep their own alerting
    alerts = [m for m in coordinator.drain_mailbox(coordinator.agents["a1"])
              if m.msg_type == "alert"]
    assert alerts, "error path still alerts the parent"

    coordinator, kid = await _finalize("weird-future-reason")
    assert kid.completion_report is not None
    assert "AUTO-SALVAGED" in kid.completion_report["summary"]
    assert "progress note" in kid.completion_report["summary"]


# -- coverage checklist + finish_scan single-bounce guard --------------------------


def _transcript(run_dir):
    return [json.loads(line) for line in
            (run_dir / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]


@pytest.mark.asyncio
async def test_finish_scan_bounces_once_without_coverage(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        "root": [("", "create_agent", {"name": "kid", "objective": "o"}),
                 ("", "wait_for_agents", {}),
                 ("", "finish_scan", {"summary": "no coverage yet"}),   # bounced
                 ("Forced through.", "finish_scan", {"summary": "second call"})],
        "kid": [("", "agent_finish", {"status": "completed", "summary": "done"})],
    })
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, completion_fn=llm)
    # the SECOND finish_scan always goes through — the exit never traps
    assert result.finished and result.summary == "second call"

    results = [e for e in _transcript(tmp_path)
               if e["type"] == "tool_result" and e.get("name") == "finish_scan"]
    assert len(results) == 2
    first, second = (json.loads(r["result"]) for r in results)
    assert first["ok"] is False and "report_coverage" in first["error"]
    for floor_class in ("auth flows", "access control", "injection", "secrets"):
        assert floor_class in first["error"]
    assert second["ok"] is True
    assert not (tmp_path / "coverage.json").exists()


@pytest.mark.asyncio
async def test_report_coverage_files_checklist_and_unblocks_finish(tmp_path):
    scope = Scope.from_target("http://t:80")
    rows = [
        {"area": "auth flows", "surface": "login + password reset",
         "status": "tested_clean", "agent": "auth-probe"},
        {"area": "injection", "surface": "search q param",
         "status": "tested_findings", "agent": "sqli-probe"},
        {"area": "upload", "surface": "none found", "status": "skipped",
         "note": "target has no upload feature"},
        {"area": "business logic", "surface": "checkout flow",
         "status": "partial", "note": "budget exhausted mid-flow"},
    ]
    llm = ScriptedLLM({
        "root": [("Filing coverage.", "report_coverage", {"rows": rows}),
                 ("Done.", "finish_scan", {"summary": "with coverage"})],
    })
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, completion_fn=llm)
    assert result.finished  # coverage filed → no bounce

    cov = json.loads((tmp_path / "coverage.json").read_text(encoding="utf-8"))
    assert cov["filed_by"] == "root" and len(cov["rows"]) == 4
    events = [e for e in _transcript(tmp_path) if e["type"] == "coverage_report"]
    assert len(events) == 1 and len(events[0]["rows"]) == 4
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    root_entry = next(a for a in state["agents"] if a["name"] == "root")
    assert root_entry["coverage_report"]["rows"][0]["area"] == "auth flows"

    # the floor-gap hint surfaces what the rows do NOT account for
    tool_results = [e for e in _transcript(tmp_path)
                    if e["type"] == "tool_result" and e.get("name") == "report_coverage"]
    payload = json.loads(tool_results[0]["result"])
    assert payload["ok"] is True and payload["filed"] == 4
    assert "access control" in payload.get("floor_gaps", [])


@pytest.mark.asyncio
async def test_report_coverage_validates_rows_and_recovers(tmp_path):
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({
        "root": [
            ("Bad status.", "report_coverage", {"rows": [
                {"area": "auth flows", "surface": "login", "status": "banana"}]}),
            ("Skipped needs a why.", "report_coverage", {"rows": [
                {"area": "upload", "surface": "x", "status": "skipped"}]}),
            ("Valid at last.", "report_coverage", {"rows": [
                {"area": "upload", "surface": "x", "status": "skipped",
                 "note": "no upload endpoints"}]}),
            ("Done.", "finish_scan", {"summary": "recovered"}),
        ],
    })
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, completion_fn=llm)
    assert result.finished and result.summary == "recovered"
    results = [json.loads(e["result"]) for e in _transcript(tmp_path)
               if e["type"] == "tool_result" and e.get("name") == "report_coverage"]
    assert results[0]["ok"] is False and "status must be one of" in results[0]["error"]
    assert results[1]["ok"] is False and "add a note saying why" in results[1]["error"]
    assert results[2]["ok"] is True


@pytest.mark.asyncio
async def test_solo_mode_never_bounces(tmp_path):
    """The bounce is root-only: solo has no report_coverage tool and its
    finish_scan must never be gated (existing contract, pinned here)."""
    from vulnem.scan import ROOT_TOOLS, SOLO_TOOLS

    assert "report_coverage" in ROOT_TOOLS
    assert "report_coverage" not in SOLO_TOOLS
    scope = Scope.from_target("http://t:80")
    llm = ScriptedLLM({"solo": [("Done.", "finish_scan", {"summary": "s"})]})
    result = await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                            run_dir=tmp_path, solo=True, completion_fn=llm)
    assert result.finished and result.stop_reason == "finish_tool"
