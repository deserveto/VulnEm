"""CI contract: exit codes and machine-readable summaries for pipelines.

`vulnem scan --ci` is headless, never prompts, prints one VULNEM_RESULT
line, and exits non-zero when findings at/above `--fail-on` severity exist
(0 = clean, 1 = findings, 2 = operational error — same shape as grep).
"""

from __future__ import annotations

from vulnem.report.findings import Finding, FindingsReport

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def ci_exit_code(findings: list[Finding], fail_on: str = "info") -> int:
    """1 when any finding is at/above the fail-on severity, else 0."""
    threshold = SEVERITY_RANK[fail_on]
    return 1 if any(SEVERITY_RANK.get(f.severity, 4) <= threshold for f in findings) else 0


def result_line(report: FindingsReport, *, fail_on: str = "info",
                exit_code: int | None = None) -> str:
    """Single machine-parseable summary line for CI logs."""
    counts = report.counts()
    counts_str = " ".join(f"{sev}={n}" for sev, n in counts.items() if n)
    code = (ci_exit_code(report.findings, fail_on)
            if exit_code is None else exit_code)
    return (f"VULNEM_RESULT target={report.target} findings={len(report.findings)} "
            f"{counts_str or 'none=1'} fail_on={fail_on} exit={code}")
