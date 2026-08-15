"""Coordinator + graph-tool tests with a scripted fake LLM and fake sandbox.

No Docker, no API key: the whole multi-agent machinery is exercised through
run_scan with completion_fn injected.
"""

import asyncio
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnem.agents.coordinator import TERMINAL_STATUSES, AgentStatus, Budget, Coordinator, Message
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

    def exec(self, command: str, *, timeout: int = 120):
        return FakeSandbox._Res()


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
    ("", "wait_for_agents", {}),
    ("", "view_agent_graph", {}),
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
        run_dir=tmp_path, completion_fn=llm, budget_turns=4,
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
    await run_scan(scope=scope, settings=make_settings(), sandbox=FakeSandbox(),
                   run_dir=tmp_path, completion_fn=llm)

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
