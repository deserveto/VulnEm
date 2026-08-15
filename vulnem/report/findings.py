"""Structured vulnerability findings and report generation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITIES = tuple(SEVERITY_ORDER)


class Finding(BaseModel):
    """One validated vulnerability finding. PoC and evidence are mandatory."""

    id: str = Field(default="", description="Stable identifier, assigned on add")
    title: str
    severity: str = Field(pattern="^(critical|high|medium|low|info)$")
    cwe: str | None = None
    description: str
    evidence: str = Field(description="Raw output proving the issue (command + response)")
    poc: str = Field(description="Step-by-step reproduction instructions")
    remediation: str
    confidence: str = Field(default="high", pattern="^(high|medium|low)$")
    url: str | None = None

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
        lines += ["", f"**Total findings: {total}**", "", "## Summary", "", self.summary, ""]

        ordered = sorted(self.findings, key=lambda f: f.sort_key())
        for i, f in enumerate(ordered, start=1):
            lines += [f"## [{f.severity.upper()}] {i}. {f.title}", ""]
            meta = [f"- Severity: {f.severity}", f"- Confidence: {f.confidence}"]
            if f.cwe:
                meta.append(f"- CWE: {f.cwe}")
            if f.url:
                meta.append(f"- URL: {f.url}")
            lines += [*meta, "", "### Description", "", f.description, ""]
            lines += ["### Proof of Concept", "", "```", f.poc.strip(), "```", ""]
            lines += ["### Evidence", "", "```", f.evidence.strip(), "```", ""]
            lines += ["### Remediation", "", f.remediation.strip(), "", "---", ""]
        return "\n".join(lines)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop near-duplicate findings by (normalized title, severity)."""
    seen: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.title.strip().lower(), f.severity)
        seen.setdefault(key, f)
    return sorted(seen.values(), key=lambda f: f.sort_key())


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def findings_from_json(path: Path) -> FindingsReport:
    return FindingsReport.model_validate(json.loads(path.read_text(encoding="utf-8")))
