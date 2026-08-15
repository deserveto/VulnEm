import sys
from pathlib import Path

import pydantic
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnem.agent.tools import truncate
from vulnem.report.findings import Finding, FindingsReport, dedupe


def make_finding(title: str, severity: str = "high", **overrides) -> Finding:
    kwargs = dict(
        title=title,
        severity=severity,
        description="d",
        evidence="e",
        poc="p",
        remediation="r",
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


def test_severity_ordering():
    findings = [make_finding("low1", "low"), make_finding("crit1", "critical"),
                make_finding("high1", "high")]
    ordered = sorted(findings, key=lambda f: f.sort_key())
    assert [f.severity for f in ordered] == ["critical", "high", "low"]


def test_dedupe_by_title_and_severity():
    items = [make_finding("SQLi in search"), make_finding("sqli in search"),
             make_finding("XSS"), make_finding("XSS"), make_finding("XSS", "low")]
    assert len(dedupe(items)) == 3


def test_cross_agent_dedupe_same_endpoint_and_class_merges():
    a = make_finding("SQL injection in search", severity="high", cwe="CWE-89",
                     url="http://shop:3000/rest/products/search", evidence="agent A evidence",
                     reported_by="sqli-hunter")
    b = make_finding("Blind SQLi in product search", severity="critical", cwe="CWE-89",
                     url="http://shop:3000/rest/products/search?q=x", evidence="agent B evidence",
                     reported_by="recon-prober", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                     cvss_score=9.8)
    out = dedupe([a, b])
    assert len(out) == 1
    merged = out[0]
    # more severe finding wins as the base; evidence merged with attribution
    assert merged.severity == "critical"
    assert "agent A evidence" in merged.evidence and "agent B evidence" in merged.evidence
    assert "sqli-hunter" in merged.reported_by and "recon-prober" in merged.reported_by
    assert merged.cvss_score == 9.8


def test_dedupe_keeps_distinct_classes_on_same_endpoint():
    sqli = make_finding("SQLi", url="http://t/search", cwe="CWE-89")
    xss = make_finding("Reflected XSS", url="http://t/search", cwe="CWE-79")
    assert len(dedupe([sqli, xss])) == 2


def test_dedupe_normalizes_endpoint_paths():
    a = make_finding("IDOR in user API", url="http://t:3000/api/users/1", cwe="CWE-639")
    b = make_finding("IDOR user api access", url="https://T:3000/api/users/2/", cwe="CWE-639")
    assert len(dedupe([a, b])) == 1


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


def test_report_markdown_shows_cvss_and_attribution(tmp_path: Path):
    f = make_finding("SQLi", cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                     cvss_score=9.8, reported_by="sqli-hunter")
    report = FindingsReport(target="http://t", started_at="a", finished_at="b",
                            model="m", summary="s", findings=[f])
    _, md_path = report.write(tmp_path)
    md = md_path.read_text(encoding="utf-8")
    assert "CVSS:3.1/AV:N" in md and "9.8" in md
    assert "Reported by: sqli-hunter" in md


def test_finding_requires_evidence_and_poc():
    with pytest.raises(pydantic.ValidationError):
        Finding(title="x", severity="high", description="d",
                remediation="r")  # missing evidence/poc
    with pytest.raises(pydantic.ValidationError):
        Finding(title="x", severity="bananas", description="d", evidence="e",
                poc="p", remediation="r")
    with pytest.raises(pydantic.ValidationError):
        Finding(title="x", severity="high", description="d", evidence="e",
                poc="p", remediation="r", cvss_score=11.5)  # out of range


def test_truncate_keeps_head_and_tail():
    text = "A" * 5000 + "MARKER" + "B" * 5000
    out = truncate(text, limit=1000)
    assert len(out) < len(text)
    assert out.startswith("A")
    assert "chars truncated" in out
    # short strings pass through untouched
    assert truncate("hello", 1000) == "hello"
