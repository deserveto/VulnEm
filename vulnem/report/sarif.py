"""SARIF 2.1.0 export: findings.json → sarif.json for CI consumption.

GitHub/GitLab surface SARIF results in PR checks (code scanning upload);
severity maps to SARIF levels, CWE becomes the rule id, and the finding's
URL (or white-box file:line) becomes the location. Fingerprints are stable
per endpoint+class so results dedupe across runs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from vulnem import __version__
from vulnem.report.findings import FindingsReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rule_id(finding) -> str:
    """Stable rule id: the CWE when known, else a slug of the title."""
    cwe = (finding.cwe or "").strip().upper()
    if cwe:
        return cwe if cwe.startswith("CWE") else f"CWE-{cwe}"
    slug = re.sub(r"[^a-z0-9]+", "-", finding.title.lower()).strip("-")
    return f"VULNEM-{slug[:48].rstrip('-')}"


def _location(finding) -> dict:
    """White-box file:line when present, else the finding's URL."""
    if finding.file:
        region = {"startLine": finding.line} if finding.line else {}
        return {"physicalLocation": {
            "artifactLocation": {"uri": finding.file},
            **({"region": region} if region else {}),
        }}
    uri = finding.url or "unknown"
    return {"physicalLocation": {"artifactLocation": {"uri": uri}}}


def report_to_sarif(report: FindingsReport) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in report.findings:
        rule_id = _rule_id(f)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.title[:120]},
                "properties": {"security-severity": _security_severity(f)},
            }
        fingerprint = re.sub(r"[^a-z0-9]+", "-", f"{f.url or 'none'} {rule_id}".lower())
        results.append({
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(rule_id),
            "level": LEVEL_BY_SEVERITY.get(f.severity, "note"),
            "message": {"text": f"{f.title}. {f.description}"},
            "locations": [_location(f)],
            "partialFingerprints": {"vulnemFinding": fingerprint[:64]},
            "properties": {
                "severity": f.severity,
                "confidence": f.confidence,
                "reported_by": f.reported_by,
                **({"cvss": f.cvss_vector} if f.cvss_vector else {}),
                **({"cvss_score": f.cvss_score} if f.cvss_score is not None else {}),
                **({"poc": f.poc} if f.poc else {}),
            },
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VulnEm",
                    "version": __version__,
                    "informationUri": "https://github.com/deserveto/VulnEm",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "target": report.target,
                "started_at": report.started_at,
                "finished_at": report.finished_at,
                "model": report.model,
                "summary": report.summary,
            },
        }],
    }


def _security_severity(finding) -> str:
    """GitHub code-scanning `security-severity` (CVSS score string or default)."""
    if finding.cvss_score is not None:
        return f"{finding.cvss_score:g}"
    return {"critical": "9.3", "high": "8.0", "medium": "5.5",
            "low": "3.0", "info": "0.0"}[finding.severity]


def write_sarif(report: FindingsReport, run_dir: Path) -> Path:
    path = run_dir / "findings.sarif"
    path.write_text(json.dumps(report_to_sarif(report), indent=2), encoding="utf-8")
    return path


def sarif_from_run(run_dir: Path) -> Path:
    from vulnem.report.findings import findings_from_json

    return write_sarif(findings_from_json(run_dir / "findings.json"), run_dir)
