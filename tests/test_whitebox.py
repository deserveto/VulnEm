"""White-box mode tests: prompt wiring + file:line/fix_patch findings."""

from __future__ import annotations

from pathlib import Path

from vulnem.agent.prompt import (
    build_root_initial_task,
    build_specialist_prompt,
    build_system_prompt,
)
from vulnem.agent.tools import ToolContext, dispatch_tool
from vulnem.report.findings import findings_from_json
from vulnem.scope import Scope

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MOUNT = "/home/pentester/source"


def test_whitebox_block_added_when_mounted() -> None:
    scope = Scope.from_target("http://vuln-app:5000")
    solo = build_system_prompt(scope, max_turns=30, whitebox_mount=MOUNT)
    assert f"READ-ONLY at {MOUNT}" in solo
    assert "semgrep --config /opt/semgrep-rules" in solo
    spec = build_specialist_prompt(scope, name="src-audit", objective="o",
                                   parent_name="root", max_turns=30,
                                   whitebox_mount=MOUNT)
    assert f"READ-ONLY at {MOUNT}" in spec
    # without a mount the prompts stay byte-identical to Phase 3
    assert MOUNT not in build_system_prompt(scope, max_turns=30)
    assert MOUNT not in build_specialist_prompt(scope, name="x", objective="o",
                                                parent_name="root", max_turns=30)


def test_root_task_mentions_whitebox_mission() -> None:
    scope = Scope.from_target("http://vuln-app:5000")
    task = build_root_initial_task(scope, whitebox_mount=MOUNT)
    assert MOUNT in task and "whitebox" in task
    assert "`whitebox` skill" in task


def test_report_finding_accepts_whitebox_fields(tmp_path: Path) -> None:
    from tests.test_agents import FakeSandbox  # reuse the offline sandbox stub

    ctx = ToolContext(
        settings=None, sandbox=FakeSandbox(), scope_host="x",  # type: ignore[arg-type]
        agent_name="src-audit", run_dir=tmp_path,
    )
    result = dispatch_tool("report_finding", {
        "title": "SQL injection in /search", "severity": "critical",
        "description": "d", "evidence": "e", "poc": "p", "remediation": "r",
        "url": "http://vuln-app:5000/search", "cwe": "CWE-89",
        "file": "server.py", "line": 75,
        "fix_patch": "--- a/server.py\n+++ b/server.py\n@@ -75 +75 @@\n-            rows = conn.execute(\n+            rows = conn.execute(\n",
    }, ctx)
    assert '"ok": true' in result
    f = ctx.findings[0]
    assert f.file == "server.py" and f.line == 75
    assert f.fix_patch and f.fix_patch.startswith("--- a/server.py")

    # round-trips through findings.json (schema keeps the new fields)
    from vulnem.report.findings import FindingsReport

    report = FindingsReport(target="http://vuln-app:5000", started_at="t0",
                            finished_at="t1", model="m", summary="s",
                            findings=ctx.findings)
    report.write(tmp_path)
    loaded = findings_from_json(tmp_path / "findings.json")
    assert loaded.findings[0].file == "server.py"
    assert loaded.findings[0].line == 75


def test_vulnapp_source_has_planted_flaws_for_semgrep() -> None:
    """The white-box demo target must keep its planted sinks (the vendored
    semgrep rules are validated against this shape at image build)."""
    src = (PROJECT_ROOT / "lab" / "vulnapp" / "server.py").read_text(encoding="utf-8")
    assert 'f"SELECT id, name, price FROM products' in src       # SQLi sink
    assert "shell=True" in src                                   # cmd injection sink
    assert "os.path.join(base, name)" in src                     # traversal sink
    assert "API_KEY = " in src and "ADMIN_PASSWORD = " in src    # secrets
    # ground truth matches the planted set
    import json

    gt = json.loads((PROJECT_ROOT / "evals" / "ground_truth" / "vuln-app.json")
                    .read_text(encoding="utf-8"))
    assert len(gt["findings"]) == 6
    assert {f["class"] for f in gt["findings"]} == {
        "sql_injection", "xss", "path_traversal", "command_injection",
        "information_disclosure", "hardcoded_secret"}
