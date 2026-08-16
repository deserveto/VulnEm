"""Cross-run findings consolidation: many runs of one target → one report.

A single scan is a sample — LLM-driven recon varies run to run, so the same
flaw can surface in one run and be missed in the next. ``merge_reports``
folds any number of completed runs (same target host) into one consolidated
report: findings key on the same normalized endpoint + vulnerability class
that backs the SARIF fingerprints, so a re-find collapses into one finding
carrying every reporting run. Evidence is stacked with per-reporter
attribution stamps, never blended.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from vulnem.report.findings import FindingsReport, dedupe


class MergeError(ValueError):
    """Consolidation refused (mixed target hosts, no runs, ...)."""


def target_host(target: str) -> str:
    try:
        return (urlsplit(target.strip()).hostname or "").lower()
    except ValueError:
        return target.strip().lower()


def merge_reports(sources: list[tuple[str, FindingsReport]]) -> tuple[FindingsReport, dict]:
    """Fold per-run reports into one consolidated report.

    ``sources`` pairs each run's id (its directory name) with its loaded
    report. Each finding is stamped with its run id (``Finding.runs``); the
    standard cross-agent dedupe then collapses re-finds, keeping the highest
    severity/confidence/CVSS seen. Returns ``(report, stats)``; raises
    :class:`MergeError` when the runs cover different target hosts —
    findings from different targets must never be blended into one report.
    """
    if not sources:
        raise MergeError("no runs to merge")
    by_host: dict[str, str] = {}
    for _, report in sources:
        by_host.setdefault(target_host(report.target), report.target)
    if len(by_host) > 1:
        detail = ", ".join(f"{rid}→{r.target}" for rid, r in sources)
        raise MergeError(f"runs cover different target hosts — refusing to "
                         f"blend findings: {detail}")

    stamped = []
    for run_id, report in sources:
        for f in report.findings:
            copy = f.model_copy()
            copy.runs = list(dict.fromkeys([*copy.runs, run_id]))
            stamped.append(copy)
    merged = dedupe(stamped)

    first = sources[0][1]
    stats = {
        "raw": len(stamped),
        "unique": len(merged),
        "duplicates": len(stamped) - len(merged),
        "per_run": {run_id: len(r.findings) for run_id, r in sources},
    }
    consolidated = FindingsReport(
        target=first.target,
        started_at=min(r.started_at for _, r in sources),
        finished_at=max(r.finished_at for _, r in sources),
        model=" + ".join(dict.fromkeys(r.model for _, r in sources)),
        summary=_summary(sources, stats),
        findings=merged,
    )
    return consolidated, stats


def _summary(sources: list[tuple[str, FindingsReport]], stats: dict) -> str:
    """Deterministic, code-generated consolidation summary (no LLM text)."""
    ids = ", ".join(run_id for run_id, _ in sources)
    lines = [
        f"Consolidated report across {len(sources)} scan runs ({ids}). "
        f"{stats['raw']} raw findings collapsed to {stats['unique']} unique "
        f"issues ({stats['duplicates']} cross-run duplicate(s) merged).",
        "",
        "One scan is a sample: agent-driven recon varies between runs, so "
        "this report unions everything these runs proved about the target. "
        "Issues found in several runs carry every reporting run under "
        '"Found in runs", with each run\'s evidence kept separately '
        "attributed; severity, confidence and CVSS shown are the maximum "
        "seen across runs.",
        "",
        "Per run:",
    ]
    for run_id, report in sources:
        counts = report.counts()
        parts = [f"{sev} {n}" for sev, n in counts.items() if n]
        lines.append(f"- {run_id} (started {report.started_at}): "
                     f"{', '.join(parts) or 'no findings'}")
    return "\n".join(lines)
