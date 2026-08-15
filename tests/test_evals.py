"""Eval harness tests: class/endpoint matching + scoring real recorded runs."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnem.evals import (
    _endpoints_compatible,
    _finding_class,
    evaluate,
    load_ground_truth,
    run_cost,
)
from vulnem.report.findings import Finding, FindingsReport, findings_from_json

GT_DIR = Path(__file__).resolve().parent.parent / "evals" / "ground_truth"
RUNS = Path(__file__).resolve().parent.parent / "runs"


def _finding(title: str, sev="high", cwe=None, url=None) -> Finding:
    return Finding(title=title, severity=sev, cwe=cwe, description="d",
                   evidence="e", poc="p", remediation="r", url=url)


def test_finding_class_extraction() -> None:
    assert _finding_class(_finding("SQL Injection in Login", cwe="CWE-89")) == "sql_injection"
    assert _finding_class(_finding("SQL injection in login (auth bypass)")) == "sql_injection"
    assert _finding_class(_finding("DOM-based XSS via search", cwe="CWE-79")) == "xss"
    assert _finding_class(_finding("Reflected XSS")) == "xss"
    assert _finding_class(_finding("Command injection in ping", cwe="CWE-78")) == "command_injection"
    assert _finding_class(_finding("Blind SSRF")) == "ssrf"
    assert _finding_class(_finding("Missing Content-Security-Policy")) == "misconfiguration"
    assert _finding_class(_finding("Unprotected /api/Users", cwe="CWE-639")) == "idor"


def test_endpoint_compatibility() -> None:
    assert _endpoints_compatible("/search?q=1", "/search")
    assert _endpoints_compatible("/api/users/1", "/api/users")
    assert _endpoints_compatible(None, "/x")       # class-only GT
    assert not _endpoints_compatible("/rest/user/login", "/rest/products/search")


def test_evaluate_recall_and_fp() -> None:
    gt = {"name": "t", "findings": [
        {"id": "g1", "class": "sql_injection", "endpoint": "/search"},
        {"id": "g2", "class": "xss", "endpoint": "/search"},
        {"id": "g3", "class": "command_injection", "endpoint": "/ping"},
    ]}
    report = FindingsReport(target="http://x", started_at="t0", finished_at="t1",
                            model="m", summary="s", findings=[
        _finding("SQLi in search", "critical", "CWE-89", "http://x/search?q=1"),
        _finding("XSS in search", "high", "CWE-79", "http://x/search"),
        _finding("Open redirect", "low"),          # false positive
    ])
    result = evaluate(report, gt)
    assert result.recall == pytest.approx(2 / 3)
    assert result.fp_rate == pytest.approx(1 / 3)
    assert result.missed_gt == ["g3"]
    assert result.false_positives == ["Open redirect"]


def test_score_real_recorded_runs() -> None:
    """The two richest real runs must score sanely against their GT:
    recall > 0, and the known-validated findings must be matched."""
    for run_dir, gt_name, must_match in (
        (RUNS / "20260815-195935-juice-shop-ea92", "juice-shop",
         {"js-sqli-login", "js-sqli-search", "js-xss-dom-search"}),
        (RUNS / "20260815-193336-dvwa-6251", "dvwa",
         {"dvwa-cmd-injection", "dvwa-sqli"}),
    ):
        gt = load_ground_truth(GT_DIR / f"{gt_name}.json")
        report = findings_from_json(run_dir / "findings.json")
        result = evaluate(report, gt)
        assert 0 < result.recall <= 1, f"{gt_name}: recall {result.recall}"
        assert must_match <= set(result.matched_gt), \
            f"{gt_name}: missing {must_match - set(result.matched_gt)}"
        assert result.fp_rate >= 0


def test_run_cost_from_real_run() -> None:
    cost = run_cost(RUNS / "20260815-195935-juice-shop-ea92")
    assert cost["tokens"] == 3_107_740
    assert cost["turns"] == 114
    assert cost["model"]
    assert cost["wall_seconds"] and cost["wall_seconds"] > 60


def test_ground_truth_files_wellformed() -> None:
    for path in sorted(GT_DIR.glob("*.json")):
        gt = load_ground_truth(path)
        assert gt["findings"], f"{path.name}: empty"
        ids = [f["id"] for f in gt["findings"]]
        assert len(ids) == len(set(ids)), f"{path.name}: duplicate ids"
        for entry in gt["findings"]:
            assert entry.get("class") and entry.get("severity")
            assert entry["severity"] in {"critical", "high", "medium", "low", "info"}
