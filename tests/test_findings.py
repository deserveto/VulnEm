import sys
from pathlib import Path

import pydantic
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnem.agent.tools import truncate
from vulnem.report.findings import Finding, FindingsReport, dedupe


def make_finding(title: str, severity: str = "high") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        description="d",
        evidence="e",
        poc="p",
        remediation="r",
    )


def test_severity_ordering():
    findings = [make_finding("low1", "low"), make_finding("crit1", "critical"),
                make_finding("high1", "high")]
    ordered = sorted(findings, key=lambda f: f.sort_key())
    assert [f.severity for f in ordered] == ["critical", "high", "low"]


def test_dedupe_by_title_and_severity():
    items = [make_finding("SQLi in search"), make_finding("sqli in search"),
             make_finding("XSS"), make_finding("XSS"), make_finding("XSS", "low")]
    assert len(dedupe(items)) == 3


def test_report_markdown_contains_findings_and_counts(tmp_path: Path):
    report = FindingsReport(
        target="http://t", started_at="a", finished_at="b", model="m",
        summary="sum", findings=[make_finding("SQLi"), make_finding("Header", "low")],
    )
    json_path, md_path = report.write(tmp_path)
    md = md_path.read_text(encoding="utf-8")
    assert "SQLi" in md and "Header" in md
    assert "| High | 1 |" in md and "| Low | 1 |" in md
    assert json_path.exists()


def test_finding_requires_evidence_and_poc():
    with pytest.raises(pydantic.ValidationError):
        Finding(title="x", severity="high", description="d",
                remediation="r")  # missing evidence/poc
    with pytest.raises(pydantic.ValidationError):
        Finding(title="x", severity="bananas", description="d", evidence="e",
                poc="p", remediation="r")


def test_truncate_keeps_head_and_tail():
    text = "A" * 5000 + "MARKER" + "B" * 5000
    out = truncate(text, limit=1000)
    assert len(out) < len(text)
    assert out.startswith("A")
    assert "chars truncated" in out
    # short strings pass through untouched
    assert truncate("hello", 1000) == "hello"
