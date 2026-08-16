"""create_agent scan-budget gate tests (offline: no Docker, no LLM).

The root's create_agent must refuse spawns the shared scan-wide budget cannot
fund (children would just die with stop_reason "scan_budget"), clamp the
child's max_turns to what is left, and always report the remaining budget.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vulnem.agents.graph_tools as graph_tools
from vulnem.agents.coordinator import Budget, Coordinator
from vulnem.agents.session import AgentSession
from vulnem.config import Settings
from vulnem.scope import Scope

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# -- fakes (minimal copies of the test_agents.py fixtures) ---------------------


class FakeSandbox:
    """Stand-in for the Docker sandbox; never exec'd in these tests."""

    source_mount = None


def make_settings(**overrides) -> Settings:
    kwargs = dict(
        model="fake/model",
        max_turns=100,
        child_max_turns=8,
        max_agents=6,
        max_total_tokens=1_000_000,
        skills_dir=PROJECT_ROOT / "skills",
    )
    kwargs.update(overrides)
    return Settings(**kwargs)


def make_root_session(tmp_path: Path, *, budget: Budget) -> AgentSession:
    """A real root session wired to a real coordinator with the given budget."""
    settings = make_settings()
    coordinator = Coordinator(run_dir=tmp_path, budget=budget)
    root = coordinator.register(
        name="root", role="root", parent_id=None,
        objective="orchestrate", max_turns=settings.max_turns,
    )
    return AgentSession(
        record=root,
        coordinator=coordinator,
        scope=Scope.from_target("http://t:80"),
        settings=settings,
        sandbox=FakeSandbox(),
        tool_names={"create_agent"},
        finish_tool="finish_scan",
        system_prompt="ROLE: ROOT ORCHESTRATOR",
        initial_task="go",
        completion_fn=None,
        run_dir=tmp_path,
    )


@pytest.fixture
def captured_spawns(monkeypatch):
    """Capture child sessions instead of running their agent loops."""
    spawned: list[AgentSession] = []
    monkeypatch.setattr(
        graph_tools, "spawn_agent_task", lambda child: spawned.append(child)
    )
    return spawned


async def spawn(sess: AgentSession, **args) -> dict:
    return json.loads(await graph_tools._tool_create_agent(sess, args))


# -- refusals --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spawn_refused_when_turns_nearly_exhausted(tmp_path, captured_spawns):
    sess = make_root_session(
        tmp_path, budget=Budget(max_turns=100, max_tokens=4_000_000)
    )
    sess.coordinator.budget.turns_used = 96
    sess.coordinator.budget.tokens_used = 100_000

    result = await spawn(sess, name="sqli-probe", objective="test sqli")

    assert result["ok"] is False
    err = result["error"]
    assert "96/100" in err and "100000/4000000" in err
    assert "finish_scan" in err and "wait_for_agents" in err
    assert "Do not spawn" in err
    assert sess.coordinator.resolve("sqli-probe") is None  # nothing registered
    assert captured_spawns == []


@pytest.mark.asyncio
async def test_spawn_refused_when_tokens_nearly_exhausted(tmp_path, captured_spawns):
    sess = make_root_session(
        tmp_path, budget=Budget(max_turns=100, max_tokens=4_000_000)
    )
    sess.coordinator.budget.turns_used = 10
    sess.coordinator.budget.tokens_used = 3_960_000

    result = await spawn(sess, name="xss-probe", objective="test xss")

    assert result["ok"] is False
    assert "3960000/4000000" in result["error"]
    assert len(sess.coordinator.agents) == 1  # only the root remains
    assert captured_spawns == []


@pytest.mark.asyncio
async def test_spawn_refused_when_only_turns_capped(tmp_path, captured_spawns):
    # turns dimension limited, tokens unlimited: the turns check alone refuses
    sess = make_root_session(tmp_path, budget=Budget(max_turns=100))
    sess.coordinator.budget.turns_used = 97

    result = await spawn(sess, name="late-probe", objective="too late")

    assert result["ok"] is False
    assert "unlimited" in result["error"]
    assert captured_spawns == []


# -- clamping ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_child_max_turns_clamped_to_remaining(tmp_path, captured_spawns):
    sess = make_root_session(
        tmp_path, budget=Budget(max_turns=100, max_tokens=4_000_000)
    )
    sess.coordinator.budget.turns_used = 88  # 12 turns left
    sess.coordinator.budget.tokens_used = 100_000

    result = await spawn(sess, name="deep-probe", objective="o", max_turns=30)

    assert result["ok"] is True
    child = sess.coordinator.resolve("deep-probe")
    assert child.max_turns == 12  # requested 30, clamped to remaining 12
    assert "clamped" in result["note"] and "30" in result["note"] and "12" in result["note"]
    assert result["scan_budget_remaining"] == {"turns": 12, "tokens": 3_900_000}
    assert captured_spawns and captured_spawns[0].record is child


# -- success responses --------------------------------------------------------------


@pytest.mark.asyncio
async def test_success_includes_remaining_budget(tmp_path, captured_spawns):
    sess = make_root_session(
        tmp_path, budget=Budget(max_turns=100, max_tokens=4_000_000)
    )
    sess.coordinator.budget.turns_used = 10
    sess.coordinator.budget.tokens_used = 50_000

    result = await spawn(sess, name="auth-probe", objective="o", max_turns=20)

    assert result["ok"] is True
    assert result["agent_id"] and result["name"] == "auth-probe"
    assert result["scan_budget_remaining"] == {"turns": 90, "tokens": 3_950_000}
    assert "clamped" not in result["note"]  # 20 requested fits in 90 remaining
    assert sess.coordinator.resolve("auth-probe").max_turns == 20


@pytest.mark.asyncio
async def test_unlimited_budgets_unaffected(tmp_path, captured_spawns):
    sess = make_root_session(tmp_path, budget=Budget())  # both dims unlimited

    result = await spawn(sess, name="probe", objective="o", max_turns=30)

    assert result["ok"] is True
    assert result["scan_budget_remaining"] == {"turns": None, "tokens": None}
    assert "clamped" not in result["note"]
    assert sess.coordinator.resolve("probe").max_turns == 30  # no clamp
    assert len(captured_spawns) == 1


@pytest.mark.asyncio
async def test_healthy_budget_registers_normally(tmp_path, captured_spawns):
    sess = make_root_session(
        tmp_path, budget=Budget(max_turns=100, max_tokens=4_000_000)
    )

    result = await spawn(sess, name="sqli-probe", objective="test the search API")

    assert result["ok"] is True
    child = sess.coordinator.resolve("sqli-probe")
    assert child is not None and child.parent_id == sess.record.agent_id
    assert child.max_turns == 8  # default from settings.child_max_turns
    assert child.role == "specialist"
    assert captured_spawns and captured_spawns[0].record.objective == "test the search API"
    events = [
        json.loads(line)
        for line in (tmp_path / "transcript.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(e["type"] == "agent_created" and e["agent"] == "sqli-probe" for e in events)


@pytest.mark.asyncio
async def test_spawn_allowed_at_exact_viability_floor(tmp_path, captured_spawns):
    # remaining == 5 turns and == 50_000 tokens is exactly viable, not refused
    sess = make_root_session(
        tmp_path, budget=Budget(max_turns=105, max_tokens=4_000_000)
    )
    sess.coordinator.budget.turns_used = 100
    sess.coordinator.budget.tokens_used = 3_950_000

    result = await spawn(sess, name="edge-probe", objective="o", max_turns=8)

    assert result["ok"] is True
    assert sess.coordinator.resolve("edge-probe").max_turns == 5  # clamped to floor
    assert result["scan_budget_remaining"] == {"turns": 5, "tokens": 50_000}
