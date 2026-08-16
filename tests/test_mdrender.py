"""Report-summary rendering tests (mdrender + wiring into md/pdf outputs)."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("reportlab")

from reportlab.platypus import Paragraph, Preformatted, Table

from vulnem.report.findings import Finding, FindingsReport
from vulnem.report.mdrender import markdown_flowables, md_inline, normalize_summary_md
from vulnem.report.pdf import _styles, report_to_pdf

NASTY = """# Security Assessment Summary: http://x

## Coverage Overview ✅
Target: http://x — 3 specialists (2 completed, **1 failed**)
| Wave | Agent | Findings |
| --- | --- | --- |
| Recon | recon-mapping | 6 |
| Auth | auth-testing | 4 |

### Findings
- [Critical] SQL injection in `/search`
- [High] JWT alg:none bypass

1. First follow-up
2. Second follow-up

```bash
curl 'http://x/search?q=%27+OR+1=1--'
```
"""


def test_normalize_summary_demotes_headings_and_strips_emoji() -> None:
    out = normalize_summary_md(NASTY)
    for line in out.splitlines():
        assert not line.startswith("# ") and not line.startswith("## ")
    assert "### Security Assessment Summary" in out   # H1 -> H3
    assert "#### Coverage Overview" in out             # H2 -> H4
    assert "✅" not in out
    # table/bullets/code stay markdown for report.md
    assert "| Wave | Agent | Findings |" in out
    assert "- [Critical] SQL injection" in out
    assert "```bash" in out


def test_normalize_summary_collapses_blank_runs() -> None:
    assert "\n\n\n" not in normalize_summary_md("a\n\n\n\nb\n")


def test_md_inline_markup() -> None:
    assert md_inline("**bold** *it* `code` <tag>") == (
        "<b>bold</b> <i>it</i> <font face=\"Courier\">code</font> &lt;tag&gt;")


def test_markdown_flowables_structure() -> None:
    flows = markdown_flowables(NASTY, _styles())
    kinds = [type(f) for f in flows]
    assert Paragraph in kinds and Table in kinds and Preformatted in kinds
    table = next(f for f in flows if isinstance(f, Table))
    assert table._cellvalues[0] == ["Wave", "Agent", "Findings"]
    assert table._cellvalues[1] == ["Recon", "recon-mapping", "6"]
    # bullets render as paragraphs with bullet dots, bold kept as markup
    bullets = [f for f in flows if isinstance(f, Paragraph) and f.bulletText == "•"]
    assert len(bullets) >= 2


def test_report_md_summary_nests_under_section(tmp_path: Path) -> None:
    report = FindingsReport(target="http://x", started_at="t0", finished_at="t1",
                            model="m", summary=NASTY, findings=[])
    report.write(tmp_path)
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    summary = md.split("## Summary", 1)[1]
    assert "## Summary" in md
    for line in summary.splitlines():
        assert not line.startswith("# ") and not line.startswith("## ")
    assert "✅" not in md


def test_pdf_summary_renders_structured(tmp_path: Path) -> None:
    finding = Finding(title="t", severity="high", description="d", evidence="e",
                      poc="p", remediation="r")
    report = FindingsReport(target="http://x", started_at="t0", finished_at="t1",
                            model="m", summary=NASTY, findings=[finding])
    out = report_to_pdf(report, tmp_path / "r.pdf")
    raw = out.read_bytes()
    assert raw.startswith(b"%PDF") and len(raw) > 2000
