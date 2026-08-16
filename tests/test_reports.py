"""SARIF + PDF export tests (Phase 4 reports)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("reportlab")

from conftest import FIXTURE_RUN

from vulnem.report.findings import Finding, FindingsReport, findings_from_json
from vulnem.report.pdf import report_to_pdf
from vulnem.report.sarif import LEVEL_BY_SEVERITY, report_to_sarif, write_sarif

RUN_DIR = FIXTURE_RUN


def _synthetic_report() -> FindingsReport:
    return FindingsReport(
        target="http://x", started_at="t0", finished_at="t1", model="m",
        summary="s",
        findings=[
            Finding(title="SQLi", severity="critical", cwe="89",
                    cvss_vector="CVSS:3.1/AV:N/AC:L", cvss_score=9.8,
                    description="d", evidence="e", poc="p", remediation="r",
                    url="http://x/search", reported_by="a"),
            Finding(title="Reflected XSS", severity="medium",
                    description="d", evidence="e", poc="p", remediation="r",
                    url="http://x/reflect", reported_by="b"),
            Finding(title="Command injection in ping", severity="high",
                    description="d", evidence="e", poc="p", remediation="r",
                    file="vuln_app.py", line=42, fix_patch="--- a\n+++ b\n",
                    url="http://x/ping", reported_by="c"),
        ],
    )


def test_sarif_structure_and_mapping(tmp_path: Path) -> None:
    sarif = report_to_sarif(_synthetic_report())
    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VulnEm"
    assert len(run["results"]) == 3
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert by_rule["CWE-89"]["level"] == "error"          # critical
    assert by_rule["VULNEM-reflected-xss"]["level"] == "warning"  # medium, no CWE
    # white-box: file:line becomes a physical location with region
    wb = by_rule["VULNEM-command-injection-in-ping"]
    loc = wb["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "vuln_app.py"
    assert loc["region"]["startLine"] == 42
    # black-box: URL is the location
    assert by_rule["CWE-89"]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "http://x/search"
    # rules unique + referenced indexes valid
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == len({r["id"] for r in rules}) == 3
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
    # fingerprints stable + unique per finding
    prints = [r["partialFingerprints"]["vulnemFinding"] for r in run["results"]]
    assert len(set(prints)) == 3
    # severity ceiling covered for every defined severity
    assert set(LEVEL_BY_SEVERITY) == {"critical", "high", "medium", "low", "info"}


def test_sarif_from_run(tmp_path: Path) -> None:
    """SARIF export from a run dir's findings.json (committed fixture)."""
    report = findings_from_json(RUN_DIR / "findings.json")
    path = write_sarif(report, tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]
    assert len(results) == len(report.findings)
    assert data["runs"][0]["properties"]["target"] == report.target
    for res in results:
        assert res["level"] in {"error", "warning", "note"}
        assert res["locations"]


def test_pdf_export(tmp_path: Path) -> None:
    out = report_to_pdf(_synthetic_report(), tmp_path / "report.pdf")
    raw = out.read_bytes()
    assert raw.startswith(b"%PDF")
    assert len(raw) > 4000
    # PDF text streams keep the finding titles (Flate-compressed pages, so
    # only check the document is multi-page: 3 findings -> >= 3 pages)
    assert raw.count(b"/Type /Page") >= 3


def test_markdown_renders_whitebox_fields(tmp_path: Path) -> None:
    report = _synthetic_report()
    report.write(tmp_path)
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "- File: vuln_app.py:42" in md
    assert "### Fix Patch" in md and "```diff" in md
