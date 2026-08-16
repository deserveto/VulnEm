"""Cross-run consolidation tests (vulnem report --merge)."""

from __future__ import annotations

import json
from pathlib import Path

from vulnem.report.findings import Finding, FindingsReport, findings_from_json
from vulnem.report.merge import MergeError, merge_reports
from vulnem.report.sarif import report_to_sarif

RUN_A = "20260816-100000-x.example-aa11"
RUN_B = "20260816-110000-x.example-bb22"


def _report(findings: list[Finding], *, target: str = "https://x.example",
            started: str = "2026-08-16T10:00:00+00:00",
            model: str = "openai/auto") -> FindingsReport:
    return FindingsReport(target=target, started_at=started,
                          finished_at=started, model=model,
                          summary="per-run summary", findings=findings)


def _finding(**kw) -> Finding:
    base = dict(title="Web session tokens remain valid after logout",
                severity="high", cwe="CWE-613", description="d", evidence="ev-A",
                poc="p", remediation="r", url="https://x.example/api/auth/logout",
                reported_by="auth-access-control")
    base.update(kw)
    return Finding(**base)


def test_refind_across_runs_collapses_with_attribution() -> None:
    """Same endpoint+class found in two runs → one finding, both runs credited."""
    a = _report([_finding(severity="high", confidence="high")])
    b = _report([_finding(title="Session tokens survive logout", severity="medium",
                          confidence="medium", evidence="ev-B",
                          reported_by="auth-recheck")])
    merged, stats = merge_reports([(RUN_A, a), (RUN_B, b)])

    assert stats["raw"] == 2 and stats["unique"] == 1 and stats["duplicates"] == 1
    assert stats["per_run"] == {RUN_A: 1, RUN_B: 1}
    f = merged.findings[0]
    assert f.runs == [RUN_A, RUN_B]
    # highest severity/confidence across runs wins
    assert f.severity == "high" and f.confidence == "high"
    # both reporters credited, evidence stacked — not blended
    assert "auth-access-control" in f.reported_by and "auth-recheck" in f.reported_by
    assert "ev-A" in f.evidence and "ev-B" in f.evidence
    assert f"also reported by auth-recheck (run {RUN_B})" in f.evidence


def test_distinct_findings_stay_separate() -> None:
    a = _report([_finding()])
    b = _report([_finding(cwe="CWE-203", url="https://x.example/api/auth/check-username",
                          title="Username enumeration")])
    merged, stats = merge_reports([(RUN_A, a), (RUN_B, b)])
    assert stats["unique"] == 2
    assert {f.cwe for f in merged.findings} == {"CWE-613", "CWE-203"}


def test_mixed_target_hosts_refused() -> None:
    a = _report([_finding()])
    b = _report([_finding()], target="https://other.example")
    try:
        merge_reports([(RUN_A, a), (RUN_B, b)])
        raise AssertionError("mixed-host merge must raise")
    except MergeError as exc:
        assert "different target hosts" in str(exc)


def test_scheme_difference_same_host_is_merged() -> None:
    a = _report([_finding()], target="https://x.example")
    b = _report([_finding()], target="http://x.example")
    _, stats = merge_reports([(RUN_A, a), (RUN_B, b)])
    assert stats["unique"] == 1


def test_self_merge_is_idempotent() -> None:
    """Merging a run with itself must not stack duplicate evidence."""
    a = _report([_finding()])
    merged, stats = merge_reports([(RUN_A, a), (RUN_A, a)])
    assert stats["unique"] == 1
    f = merged.findings[0]
    assert f.evidence.count("ev-A") == 1
    assert "also reported by" not in f.evidence
    assert f.runs == [RUN_A]


def test_summary_is_generated_and_counts_runs() -> None:
    a = _report([_finding()])
    b = _report([_finding(cwe="CWE-203", url="https://x.example/cu",
                          title="Username enumeration")])
    merged, _ = merge_reports([(RUN_A, a), (RUN_B, b)])
    for needle in (RUN_A, RUN_B, "2 scan runs", "2 unique", "maximum"):
        assert needle in merged.summary
    # per-run agent summaries are never blended into the consolidated one
    assert "per-run summary" not in merged.summary


def test_markdown_and_sarif_expose_runs() -> None:
    a = _report([_finding()])
    b = _report([_finding(evidence="ev-B", reported_by="auth-recheck")])
    merged, _ = merge_reports([(RUN_A, a), (RUN_B, b)])

    md = merged.to_markdown()
    assert f"Found in runs: {RUN_A}, {RUN_B}" in md

    result = report_to_sarif(merged)["runs"][0]["results"][0]
    assert result["properties"]["runs"] == [RUN_A, RUN_B]


def _seed_run(root: Path, run_id: str, findings: list[Finding]) -> Path:
    run_dir = root / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "findings.json").write_text(
        _report(findings).model_dump_json(indent=2), encoding="utf-8")
    return run_dir


def test_cli_merge_writes_full_report_set(tmp_path: Path) -> None:
    from vulnem.cli import main

    a = _seed_run(tmp_path, RUN_A, [_finding()])
    b = _seed_run(tmp_path, RUN_B, [_finding(severity="medium", evidence="ev-B",
                                             reported_by="auth-recheck")])
    out = tmp_path / "merged"
    rc = main(["report", "--merge", str(a), str(b), "--out", str(out)])
    assert rc == 0

    for name in ("findings.json", "report.md", "findings.sarif", "report.pdf",
                 "config.json"):
        assert (out / name).is_file(), name
    report = findings_from_json(out / "findings.json")
    assert len(report.findings) == 1
    assert report.findings[0].runs == [RUN_A, RUN_B]
    config = json.loads((out / "config.json").read_text(encoding="utf-8"))
    assert config["merged"] is True and config["sources"] == [RUN_A, RUN_B]


def test_cli_merge_missing_findings_fails(tmp_path: Path) -> None:
    from vulnem.cli import main

    empty = tmp_path / RUN_A
    empty.mkdir()
    assert main(["report", "--merge", str(empty), "--out",
                str(tmp_path / "o")]) == 2


def test_cli_merge_default_out_lands_in_runs_dir(tmp_path: Path, monkeypatch) -> None:
    from vulnem import cli

    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    a = _seed_run(tmp_path, RUN_A, [_finding()])

    class FakeSettings:
        runs_dir = runs_root
        sandbox_image = "vulnem-sandbox:latest"

        @staticmethod
        def load(*, project_root=None):
            return FakeSettings

    monkeypatch.setattr(cli, "Settings", FakeSettings)
    monkeypatch.setattr(cli, "_resolve_paths", lambda s: s)
    rc = cli.main(["report", "--merge", str(a)])
    assert rc == 0
    outs = list(runs_root.iterdir())
    assert len(outs) == 1 and "-merged-" in outs[0].name
    assert "x.example" in outs[0].name
