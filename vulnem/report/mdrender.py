"""Render agent-written markdown (the root summary) into report surfaces.

The finish_scan summary is free-form LLM markdown: top-level headings,
tables, bullets, bold, emoji. Two consumers need different treatment:

- report.md: keep it markdown, but DEMOTE headings so the summary nests
  under the report's own ``## Summary`` section instead of hijacking the
  document hierarchy.
- report.pdf: render it as real flowables (headings, bullet lists, tables,
  code fences) instead of one escaped text blob; strip glyphs the PDF's
  built-in fonts cannot draw (emoji, box-drawing symbols).
"""

from __future__ import annotations

import re

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_FENCE_RE = re.compile(r"^```")
_TABLE_SEP_RE = re.compile(r"^\s*\|?[\s:|-]+\|?\s*$")
_BULLET_RE = re.compile(r"^\s*([-*+]|\d+[.)])\s+")
# glyphs Helvetica can't draw (emoji, dingbats, box-drawing)
_UNPRINTABLE_RE = re.compile(
    "[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F\u2190-\u21FF\u2500-\u25FF]")


def normalize_summary_md(text: str, *, demote: int = 2) -> str:
    """Make an agent summary safe to embed under ``## Summary``:
    demote every heading by `demote` levels (capped at 6), drop emoji-ish
    glyphs that render as boxes, collapse runs of blank lines."""
    out: list[str] = []
    blanks = 0
    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if m:
            level = min(len(m.group(1)) + demote, 6)
            content = _UNPRINTABLE_RE.sub("", m.group(2)).strip()
            line = f"{'#' * level} {content}" if content else ""
        else:
            line = _UNPRINTABLE_RE.sub("", line)
        if not line.strip():
            blanks += 1
            if blanks > 1:
                continue
        else:
            blanks = 0
        out.append(line.rstrip())
    return "\n".join(out).strip()


def md_inline(text: str) -> str:
    """Escape XML and convert inline markdown to reportlab paragraph markup."""
    text = _UNPRINTABLE_RE.sub("", text)
    text = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<i>\1</i>", text)
    text = re.sub(r"`([^`]+)`", r'<font face="Courier">\1</font>', text)
    return text


def _split_table_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def markdown_flowables(text: str, styles: dict):
    """Parse lightweight markdown into reportlab flowables.

    Handles: fenced code blocks, ATX headings, pipe tables, bullet/ordered
    lists, plain paragraphs. Everything else falls back to a paragraph.
    """
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Preformatted, Spacer, Table, TableStyle

    flows: list = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if _FENCE_RE.match(line):
            block: list[str] = []
            i += 1
            while i < len(lines) and not _FENCE_RE.match(lines[i]):
                block.append(lines[i])
                i += 1
            i += 1  # closing fence
            flows.append(Preformatted("\n".join(block), styles["code"]))
            continue
        m = _HEADING_RE.match(line)
        if m:
            level = min(len(m.group(1)), 4)
            flows.append(Paragraph(md_inline(m.group(2)),
                                   styles.get(f"h{level + 1}", styles["h3"])))
            i += 1
            continue
        if line.lstrip().startswith("|") and i + 1 < len(lines) \
                and _TABLE_SEP_RE.match(lines[i + 1]):
            header = _split_table_row(line)
            i += 2
            rows = [header]
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(_split_table_row(lines[i]))
                i += 1
            width = max(len(header), *(len(r) for r in rows)) if rows else len(header)
            rows = [r + [""] * (width - len(r)) for r in rows]
            table = Table(rows, hAlign="LEFT")
            table.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecf0f1")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bdc3c7")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            flows += [Spacer(1, 4), table, Spacer(1, 6)]
            continue
        if _BULLET_RE.match(line):
            items: list[str] = []
            while i < len(lines) and _BULLET_RE.match(lines[i]):
                items.append(_BULLET_RE.sub("", lines[i]).strip())
                i += 1
            for item in items:
                flows.append(Paragraph(md_inline(item), styles["list_item"],
                                       bulletText="•"))
            flows.append(Spacer(1, 4))
            continue
        # paragraph: consume until blank/structural line
        para: list[str] = []
        while i < len(lines) and lines[i].strip() \
                and not _HEADING_RE.match(lines[i]) \
                and not _BULLET_RE.match(lines[i]) \
                and not _FENCE_RE.match(lines[i]) \
                and not lines[i].lstrip().startswith("|"):
            para.append(lines[i].strip())
            i += 1
        flows.append(Paragraph(md_inline(" ".join(para)), styles["body"]))
    return flows
