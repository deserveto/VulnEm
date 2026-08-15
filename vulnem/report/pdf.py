"""PDF export of a findings report (reportlab platypus).

Renders straight from the ``FindingsReport`` model — severity summary
table, one section per finding (meta, description, PoC, evidence,
remediation, optional fix patch). Monospace for anything an operator
would copy-paste.
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from vulnem.report.findings import SEVERITIES, FindingsReport

SEVERITY_HEX = {
    "critical": colors.HexColor("#c0392b"),
    "high": colors.HexColor("#e74c3c"),
    "medium": colors.HexColor("#e67e22"),
    "low": colors.HexColor("#2980b9"),
    "info": colors.HexColor("#7f8c8d"),
}


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    mono = "Courier"
    return {
        "title": ParagraphStyle("VTitle", parent=base["Title"], fontSize=20, leading=24),
        "meta": ParagraphStyle("VMeta", parent=base["Normal"], fontSize=9,
                               textColor=colors.HexColor("#444444"), leading=12),
        "h2": ParagraphStyle("VH2", parent=base["Heading2"], spaceBefore=14),
        "h3": ParagraphStyle("VH3", parent=base["Heading3"], spaceBefore=10,
                             spaceAfter=4),
        "body": ParagraphStyle("VBody", parent=base["Normal"], leading=13),
        "code": ParagraphStyle("VCode", fontName=mono, fontSize=7.5, leading=9.5),
        "sev": {sev: ParagraphStyle(
            f"VSev{sev}", parent=base["Heading3"], textColor=hex_color,
        ) for sev, hex_color in SEVERITY_HEX.items()},
    }


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _code_block(text: str, style) -> Preformatted:
    return Preformatted(text.strip() or "(none)", style)


def report_to_pdf(report: FindingsReport, out_path: Path) -> Path:
    styles = _styles()
    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"VulnEm Security Assessment — {report.target}",
    )
    story: list = [
        Paragraph("VulnEm Security Assessment Report", styles["title"]),
        Spacer(1, 4),
        Paragraph(_escape(
            f"Target: {report.target} &nbsp;·&nbsp; Model: {report.model}<br/>"
            f"Started: {report.started_at} &nbsp;·&nbsp; Finished: {report.finished_at}"
        ), styles["meta"]),
        Spacer(1, 10),
    ]

    counts = report.counts()
    story.append(Paragraph("Severity Summary", styles["h2"]))
    rows = [["Severity", "Count"]] + [
        [sev.title(), str(counts.get(sev, 0))] for sev in SEVERITIES
    ] + [["Total", str(len(report.findings))]]
    table = Table(rows, colWidths=[40 * mm, 25 * mm], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecf0f1")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bdc3c7")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8f9f9")]),
    ]))
    story += [table, Spacer(1, 12), Paragraph("Summary", styles["h2"]),
              Paragraph(_escape(report.summary), styles["body"])]

    ordered = sorted(report.findings, key=lambda f: f.sort_key())
    for i, f in enumerate(ordered, start=1):
        story.append(PageBreak() if i > 1 else Spacer(1, 12))
        story.append(Paragraph(
            _escape(f"[{f.severity.upper()}] {i}. {f.title}"),
            styles["sev"].get(f.severity, styles["h3"]),
        ))
        meta = [f"Severity: {f.severity}", f"Confidence: {f.confidence}"]
        if f.cvss_vector:
            score = f" ({f.cvss_score:g})" if f.cvss_score is not None else ""
            meta.append(f"CVSS: {f.cvss_vector}{score}")
        if f.cwe:
            meta.append(f"CWE: {f.cwe}")
        if f.url:
            meta.append(f"URL: {f.url}")
        if f.file:
            meta.append(f"File: {f.file}" + (f":{f.line}" if f.line else ""))
        if f.reported_by:
            meta.append(f"Reported by: {f.reported_by}")
        story += [Paragraph(_escape(" &nbsp;·&nbsp; ".join(meta)), styles["meta"]),
                  Spacer(1, 6), Paragraph("Description", styles["h3"]),
                  Paragraph(_escape(f.description), styles["body"]),
                  Paragraph("Proof of Concept", styles["h3"]),
                  _code_block(f.poc, styles["code"]),
                  Paragraph("Evidence", styles["h3"]),
                  _code_block(f.evidence, styles["code"]),
                  Paragraph("Remediation", styles["h3"]),
                  Paragraph(_escape(f.remediation), styles["body"])]
        if f.fix_patch and f.fix_patch.strip():
            story += [Paragraph("Fix Patch", styles["h3"]),
                      _code_block(f.fix_patch, styles["code"])]

    doc.build(story)
    return out_path


def pdf_from_run(run_dir: Path) -> Path:
    from vulnem.report.findings import findings_from_json

    return report_to_pdf(findings_from_json(run_dir / "findings.json"),
                         run_dir / "report.pdf")
