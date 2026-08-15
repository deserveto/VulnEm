"""CI mode tests: exit-code contract + PR-diff focus extraction."""

from __future__ import annotations

from pathlib import Path

from vulnem.agent.prompt import build_initial_task, build_root_initial_task
from vulnem.ci import ci_exit_code, result_line
from vulnem.diffs import focus_directive, load_focus, parse_unified_diff
from vulnem.report.findings import Finding, FindingsReport
from vulnem.scope import Scope

SAMPLE_DIFF = """\
diff --git a/app/routes/search.py b/app/routes/search.py
index 123..456 100644
--- a/app/routes/search.py
+++ b/app/routes/search.py
@@ -10,4 +10,7 @@ def search():
-    rows = db.query(f"SELECT * FROM products WHERE name LIKE '%{q}%'")
+    # endpoint /api/v2/search now delegates to the new service
+    resp = requests.get("http://internal:9000/api/products")
+    return jsonify(resp.json())
diff --git a/static/app.js b/static/app.js
--- a/static/app.js
+++ b/static/app.js
@@ -1,2 +1,3 @@
+    fetch('/rest/user/whoami').then(r => r.json())
+    // also touches /rest/user/login
"""


def _finding(sev: str) -> Finding:
    return Finding(title="t", severity=sev, description="d", evidence="e",
                   poc="p", remediation="r")


def test_ci_exit_code_thresholds() -> None:
    crit, low = _finding("critical"), _finding("low")
    assert ci_exit_code([]) == 0
    assert ci_exit_code([low], "info") == 1
    assert ci_exit_code([low], "low") == 1
    assert ci_exit_code([low], "medium") == 0      # low < medium threshold
    assert ci_exit_code([crit], "critical") == 1
    assert ci_exit_code([crit, low], "high") == 1
    # fail_on=high with only a low finding -> clean exit
    assert ci_exit_code([low], "high") == 0


def test_result_line_machine_readable() -> None:
    report = FindingsReport(target="http://x", started_at="t0", finished_at="t1",
                            model="m", summary="s",
                            findings=[_finding("critical"), _finding("low")])
    line = result_line(report, fail_on="critical", exit_code=1)
    assert line.startswith("VULNEM_RESULT target=http://x findings=2")
    assert "critical=1" in line and "low=1" in line
    assert "fail_on=critical exit=1" in line


def test_parse_unified_diff_extracts_files_and_endpoints() -> None:
    focus = parse_unified_diff(SAMPLE_DIFF)
    assert "app/routes/search.py" in focus.files
    assert "static/app.js" in focus.files
    # endpoints from added lines; asset-looking paths filtered out
    assert "/api/v2/search" in focus.endpoints or "/api/products" in focus.endpoints
    assert "/rest/user/whoami" in focus.endpoints
    assert "/rest/user/login" in focus.endpoints
    assert all(not e.endswith(".js") for e in focus.endpoints)


def test_load_focus_from_file(tmp_path: Path) -> None:
    diff = tmp_path / "pr.diff"
    diff.write_text(SAMPLE_DIFF, encoding="utf-8")
    focus = load_focus(diff_file=str(diff))
    assert focus is not None and not focus.is_empty()
    assert focus.files[0] == "app/routes/search.py"


def test_load_focus_no_diff_returns_none(tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_text("not a diff at all\n", encoding="utf-8")
    focus = load_focus(diff_file=str(empty))
    assert focus is not None and focus.is_empty()
    assert load_focus() is None  # no inputs at all


def test_focus_directive_flows_into_initial_task() -> None:
    focus = parse_unified_diff(SAMPLE_DIFF)
    directive = focus_directive(focus)
    assert "SCOPE MODE: diff" in directive
    assert "app/routes/search.py" in directive
    scope = Scope.from_target("http://juice-shop:3000")
    root_task = build_root_initial_task(scope, focus=directive)
    solo_task = build_initial_task(scope, focus=directive)
    assert directive in root_task and directive in solo_task
    # without focus, tasks stay unchanged (no narrowing text)
    assert "SCOPE MODE" not in build_root_initial_task(scope)
