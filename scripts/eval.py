"""Eval harness: scan lab targets (or score recorded runs) against ground
truth — recall, false-positive rate, cost per run.

Usage:
  # score every recorded run against its target's ground truth (no LLM):
  python scripts/eval.py --runs runs/

  # launch fresh scans for one or more targets, then score:
  python scripts/eval.py --scan juice-shop --scan dvwa
  python scripts/eval.py --scan vuln-app            # white-box (source mounted)

  # score one specific run:
  python scripts/eval.py --run-dir runs/20260815-195935-juice-shop-ea92

Results: markdown + json tables under evals/results/.
Exit codes: 0 = table produced, 2 = usage/scan failure.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vulnem.evals import evaluate, load_ground_truth, run_cost  # noqa: E402
from vulnem.report.findings import findings_from_json  # noqa: E402

GT_DIR = PROJECT_ROOT / "evals" / "ground_truth"
RESULTS_DIR = PROJECT_ROOT / "evals" / "results"


def _load_targets() -> dict:
    data = json.loads((PROJECT_ROOT / "evals" / "targets.json").read_text(encoding="utf-8"))
    return data["targets"]


def _gt_for_run(run_dir: Path, targets: dict) -> tuple[str, dict] | None:
    """Find the ground truth matching a run dir's target host."""
    config = run_dir / "config.json"
    if not config.is_file():
        return None
    try:
        target = json.loads(config.read_text(encoding="utf-8"))["target"]
    except (json.JSONDecodeError, KeyError):
        return None
    from urllib.parse import urlsplit

    host = urlsplit(target).hostname or ""
    for name, spec in targets.items():
        if urlsplit(spec["target"]).hostname == host:
            gt_path = GT_DIR / f"{spec['gt']}.json"
            if gt_path.is_file():
                return name, load_ground_truth(gt_path)
    return None


def _score_run(run_dir: Path, gt: dict) -> dict:
    report = findings_from_json(run_dir / "findings.json")
    result = evaluate(report, gt)
    row = result.row()
    row.update(run_cost(run_dir))
    row["run_dir"] = str(run_dir)
    return row


def _launch_scan(name: str, spec: dict, *, extra: list[str] | None = None) -> Path | None:
    """Run `vulnem scan` for a registry target; return its run dir (or None)."""
    cmd = [sys.executable, "-m", "vulnem.cli", "scan", spec["target"],
           "--network", spec["network"], "--yes",
           "--budget", str(spec.get("budget", 200))]
    if spec.get("creds"):
        cmd += ["--creds", str(PROJECT_ROOT / spec["creds"])]
    if spec.get("source"):
        cmd += ["--source", str(PROJECT_ROOT / spec["source"])]
    cmd += extra or []
    print(f"[eval] scanning {name}: {' '.join(cmd[3:])}")
    started = time.time()
    proc = subprocess.run(cmd, cwd=PROJECT_ROOT)
    took = time.time() - started
    print(f"[eval] scan exit={proc.returncode} ({took:.0f}s)")
    run_dirs = sorted((PROJECT_ROOT / "runs").glob("*"),
                      key=lambda p: p.stat().st_mtime)
    if not run_dirs:
        return None
    newest = run_dirs[-1]
    config = newest / "config.json"
    if config.is_file():
        try:
            if json.loads(config.read_text(encoding="utf-8"))["target"] != spec["target"]:
                print(f"[eval] newest run dir {newest.name} is not {name}; skipping")
                return None
        except (json.JSONDecodeError, KeyError):
            return None
    return newest


def _render_table(rows: list[dict]) -> str:
    lines = [
        "# VulnEm eval results",
        "",
        f"_generated {datetime.now(UTC).isoformat(timespec='seconds')}_",
        "",
        "| run | gt | findings | GT | recall | FP rate | turns | tokens | wall |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        lines.append(
            f"| {Path(r['run_dir']).name} | {r['gt']} | {r['findings']} | "
            f"{r['ground_truth']} | {r['recall']:.0%} | {r['fp_rate']:.0%} | "
            f"{r.get('turns') or '—'} | {r.get('tokens') or '—'} | "
            f"{r.get('wall_seconds') or '—'}s |")
    lines += ["", "## Detail", ""]
    for r in rows:
        lines += [
            f"### {Path(r['run_dir']).name} — recall {r['recall']:.0%}, "
            f"FP {r['fp_rate']:.0%} (model {r.get('model') or '?'})",
            "",
            f"- matched: {', '.join(r['matched']) or '—'}",
            f"- missed: {', '.join(r['missed']) or '—'}",
            f"- false positives: {', '.join(r['false_positives']) or '—'}",
            "",
        ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scan", action="append", default=[],
                        help="target name from evals/targets.json (repeatable)")
    parser.add_argument("--run-dir", type=Path, help="score this run dir only")
    parser.add_argument("--runs", type=Path, help="score every run dir under this root")
    parser.add_argument("--min-tokens", type=int, default=100_000,
                        help="skip runs below this token count (aborted scans)")
    args = parser.parse_args(argv)

    targets = _load_targets()
    rows: list[dict] = []

    for name in args.scan:
        spec = targets.get(name)
        if spec is None:
            print(f"[eval] unknown target {name!r} (known: {', '.join(targets)})")
            return 2
        run_dir = _launch_scan(name, spec)
        if run_dir is None:
            print(f"[eval] scan for {name} produced no run dir")
            return 2
        gt_path = GT_DIR / f"{spec['gt']}.json"
        rows.append(_score_run(run_dir, load_ground_truth(gt_path)))

    if args.run_dir:
        found = _gt_for_run(args.run_dir.resolve(), targets)
        if found is None:
            print(f"[eval] no ground truth matches {args.run_dir}")
            return 2
        rows.append(_score_run(args.run_dir.resolve(), found[1]))

    if args.runs:
        for run_dir in sorted(args.runs.resolve().glob("*")):
            if not (run_dir / "findings.json").is_file():
                continue
            found = _gt_for_run(run_dir, targets)
            if found is None:
                continue
            cost = run_cost(run_dir)
            if (cost.get("tokens") or 0) < args.min_tokens:
                continue  # aborted/demo plumbing runs
            rows.append(_score_run(run_dir, found[1]))

    if not rows:
        print("[eval] nothing to score (use --scan/--run-dir/--runs)")
        return 2

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    table = _render_table(rows)
    (RESULTS_DIR / f"{stamp}.md").write_text(table, encoding="utf-8")
    (RESULTS_DIR / f"{stamp}.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8")
    print(table)
    print(f"\n[eval] wrote {RESULTS_DIR / stamp}.md and .json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
