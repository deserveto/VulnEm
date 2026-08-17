"""Structured vulnerability findings and report generation."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITIES = tuple(SEVERITY_ORDER)
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


class Finding(BaseModel):
    """One validated vulnerability finding. PoC and evidence are mandatory."""

    id: str = Field(default="", description="Stable identifier, assigned on add")
    title: str
    severity: str = Field(pattern="^(critical|high|medium|low|info)$")
    cwe: str | None = None
    cvss_vector: str | None = Field(
        default=None, description="CVSS vector string, e.g. CVSS:3.1/AV:N/AC:L/..."
    )
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    description: str
    evidence: str = Field(description="Raw output proving the issue (command + response)")
    poc: str = Field(description="Step-by-step reproduction instructions")
    remediation: str
    confidence: str = Field(default="high", pattern="^(high|medium|low)$")
    url: str | None = None
    reported_by: str = Field(default="", description="Agent that filed the finding")
    file: str | None = Field(default=None,
                             description="Source file (white-box mode), e.g. app.py")
    line: int | None = Field(default=None, ge=1,
                             description="Line in `file` where the flaw lives")
    fix_patch: str | None = Field(default=None,
                                  description="Unified diff fixing the finding")
    runs: list[str] = Field(default_factory=list,
                            description="Runs that reported this finding "
                                        "(cross-run consolidation; empty for a live scan)")

    def sort_key(self) -> tuple[int, str]:
        return (SEVERITY_ORDER.get(self.severity, 99), self.title.lower())


class FindingsReport(BaseModel):
    """Everything a scan produced, ready to serialize."""

    target: str
    started_at: str
    finished_at: str
    model: str
    summary: str
    findings: list[Finding] = []
    coverage: list[dict[str, str]] = Field(
        default_factory=list,
        description="Coverage checklist rows filed by root via report_coverage "
                    "(area/surface/status/agent/note); empty = none filed.",
    )

    def counts(self) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def write(self, out_dir: Path) -> tuple[Path, Path]:
        """Write findings.json + report.md; returns their paths."""
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "findings.json"
        md_path = out_dir / "report.md"
        json_path.write_text(
            self.model_dump_json(indent=2), encoding="utf-8"
        )
        md_path.write_text(self.to_markdown(), encoding="utf-8")
        return json_path, md_path

    def to_markdown(self) -> str:
        from vulnem.report.mdrender import normalize_summary_md

        counts = self.counts()
        total = len(self.findings)
        lines = [
            "# VulnEm Security Assessment Report",
            "",
            f"- **Target:** {self.target}",
            f"- **Started:** {self.started_at}",
            f"- **Finished:** {self.finished_at}",
            f"- **Model:** {self.model}",
            "",
            "## Severity Summary",
            "",
            "| Severity | Count |",
            "| --- | --- |",
        ]
        for sev in SEVERITIES:
            lines.append(f"| {sev.title()} | {counts.get(sev, 0)} |")
        lines += ["", f"**Total findings: {total}**", "", "## Summary", "",
                  # the agent summary is free-form markdown; demote its
                  # headings so it nests under this section instead of
                  # hijacking the document hierarchy
                  normalize_summary_md(self.summary), ""]
        lines += _coverage_section(self.coverage)

        ordered = sorted(self.findings, key=lambda f: f.sort_key())
        for i, f in enumerate(ordered, start=1):
            lines += [f"## [{f.severity.upper()}] {i}. {f.title}", ""]
            meta = [f"- Severity: {f.severity}", f"- Confidence: {f.confidence}"]
            if f.cvss_vector:
                score = f" ({f.cvss_score:g})" if f.cvss_score is not None else ""
                meta.append(f"- CVSS: {f.cvss_vector}{score}")
            if f.cwe:
                meta.append(f"- CWE: {f.cwe}")
            if f.url:
                meta.append(f"- URL: {f.url}")
            if f.file:
                meta.append(f"- File: {f.file}" + (f":{f.line}" if f.line else ""))
            if f.reported_by:
                meta.append(f"- Reported by: {f.reported_by}")
            if f.runs:
                meta.append(f"- Found in runs: {', '.join(f.runs)}")
            lines += [*meta, "", "### Description", "", f.description, ""]
            lines += ["### Proof of Concept", "", "```", f.poc.strip(), "```", ""]
            lines += ["### Evidence", "", "```", f.evidence.strip(), "```", ""]
            lines += ["### Remediation", "", f.remediation.strip()]
            if f.fix_patch and f.fix_patch.strip():
                lines += ["", "### Fix Patch", "", "```diff", f.fix_patch.strip(), "```"]
            lines += ["", "---", ""]
        return "\n".join(lines)


_COVERAGE_STATUS_LABELS = {
    "tested_clean": "tested — clean",
    "tested_findings": "tested — findings",
    "skipped": "skipped",
    "partial": "partial",
}


def _coverage_section(coverage: list[dict[str, str]]) -> list[str]:
    """Render the root's coverage checklist: what was tested (clean or with
    findings), what was skipped and why. Absent when root filed none."""
    if not coverage:
        return []
    counts: dict[str, int] = {}
    for row in coverage:
        status = str(row.get("status") or "?")
        counts[status] = counts.get(status, 0) + 1
    tally = " · ".join(
        f"{n} {_COVERAGE_STATUS_LABELS.get(s, s)}" for s, n in
        sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    lines = [
        "## Coverage",
        "",
        "Areas the orchestrator accounted for before finishing. Skipped and",
        "partial rows carry the reason in their note.",
        "",
        f"*{tally}*",
        "",
        "| Area | Surface | Status | Agent | Note |",
        "| --- | --- | --- | --- | --- |",
    ]

    def _cell(row: dict[str, str], key: str) -> str:
        value = str(row.get(key) or "").strip()
        return value.replace("|", "\\|").replace("\n", " ") or "—"

    for row in coverage:
        status = str(row.get("status") or "")
        status_cell = _COVERAGE_STATUS_LABELS.get(status, status) or "—"
        lines.append(
            "| " + " | ".join((_cell(row, "area"), _cell(row, "surface"),
                                status_cell, _cell(row, "agent"),
                                _cell(row, "note"))) + " |"
        )
    return [*lines, "", ""]


def _normalize_endpoint(url: str) -> str:
    """Reduce a URL to its comparable endpoint key.

    Path only, lowercase, trailing slash stripped, and digit-only segments
    collapsed to ``{id}`` — /api/users/1 and /api/users/2 are the same
    endpoint for finding-dedupe purposes (IDOR affects the collection).
    """
    try:
        parts = urlsplit(url.strip())
        path = parts.path or "/"
        segments = ("{id}" if seg.isdigit() else seg for seg in path.split("/"))
        normalized = "/".join(segments).rstrip("/").lower()
        return normalized or "/"
    except ValueError:
        return url.strip().lower()


def _class_key(finding: Finding) -> str:
    """Vulnerability class: CWE when known, else salient title tokens."""
    if finding.cwe:
        return finding.cwe.strip().upper()
    stop = {"the", "a", "an", "in", "on", "of", "via", "to", "and", "with", "at", "by"}
    tokens = [t for t in re.findall(r"[a-z0-9]+", finding.title.lower()) if t not in stop]
    return " ".join(tokens[:4])


def _merge_duplicate(base: Finding, dup: Finding) -> Finding:
    """Collapse two findings on the same endpoint+class into one, merging evidence."""
    if SEVERITY_ORDER.get(dup.severity, 99) < SEVERITY_ORDER.get(base.severity, 99):
        base, dup = dup, base
    attribution = dup.reported_by or "another agent"
    if dup.runs:
        attribution += f" (run {', '.join(dup.runs)})"
    # A run already credited on `base` re-reporting the same issue (merging a
    # run with itself) must not stack its own evidence a second time.
    if not (dup.runs and set(dup.runs) <= set(base.runs)):
        base.evidence = (
            f"{base.evidence.rstrip()}\n\n--- also reported by {attribution} ---\n{dup.evidence.rstrip()}"
        )
    if not base.poc.strip() and dup.poc.strip():
        base.poc = dup.poc
    if CONFIDENCE_ORDER.get(dup.confidence, 0) > CONFIDENCE_ORDER.get(base.confidence, 0):
        base.confidence = dup.confidence
    if dup.cvss_score is not None and (base.cvss_score is None or dup.cvss_score > base.cvss_score):
        base.cvss_score = dup.cvss_score
        base.cvss_vector = dup.cvss_vector or base.cvss_vector
    names = [n for n in (base.reported_by, dup.reported_by) if n]
    base.reported_by = ", ".join(dict.fromkeys(names))
    base.runs = list(dict.fromkeys([*base.runs, *dup.runs]))
    return base


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicates across agents.

    Same endpoint + same vulnerability class merges into one finding with
    merged evidence and attribution (agents overlap; the report must not).
    Findings without a URL fall back to the (title, severity) key.
    """
    by_endpoint: dict[tuple[str, str], Finding] = {}
    by_title: dict[tuple[str, str], Finding] = {}
    for f in findings:
        if f.url:
            key = (_normalize_endpoint(f.url), _class_key(f))
            if key in by_endpoint:
                by_endpoint[key] = _merge_duplicate(by_endpoint[key], f)
            else:
                by_endpoint[key] = f
        else:
            key = (f.title.strip().lower(), f.severity)
            if key in by_title:
                by_title[key] = _merge_duplicate(by_title[key], f)
            else:
                by_title[key] = f
    merged = list(by_endpoint.values()) + list(by_title.values())
    return sorted(merged, key=lambda f: f.sort_key())


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def findings_from_json(path: Path) -> FindingsReport:
    return FindingsReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
