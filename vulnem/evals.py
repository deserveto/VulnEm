"""Eval harness core: match findings against ground truth, score recall/FP/cost.

Ground truth format (evals/ground_truth/<name>.json):

    {"target": "...", "findings": [
        {"id": "...", "title": "...", "class": "sql_injection",
         "cwe": "CWE-89", "endpoint": "/rest/user/login", "severity": "critical"},
        ...]}

A finding matches a GT entry when the vulnerability class is compatible
(canonical CWE class, or class tokens present in the finding title) AND the
endpoint is compatible (normalized-path equality/prefix, when both sides
carry one). Everything unmatched on the finding side counts toward the
false-positive rate — the honest cost of prompt regressions.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from vulnem.report.findings import Finding, FindingsReport

# canonical class per CWE (findings may carry either form)
CWE_CLASS = {
    "CWE-89": "sql_injection",
    "CWE-79": "xss",
    "CWE-78": "command_injection",
    "CWE-77": "command_injection",
    "CWE-22": "path_traversal",
    "CWE-98": "file_inclusion",
    "CWE-200": "information_disclosure",
    "CWE-798": "hardcoded_secret",
    "CWE-639": "idor",
    "CWE-284": "broken_access_control",
    "CWE-862": "broken_access_control",
    "CWE-863": "broken_access_control",
    "CWE-347": "broken_auth",
    "CWE-287": "broken_auth",
    "CWE-352": "csrf",
    "CWE-434": "file_upload",
    "CWE-918": "ssrf",
    "CWE-1336": "ssti",
    "CWE-94": "code_execution",
    "CWE-95": "code_execution",
    "CWE-601": "open_redirect",
    "CWE-548": "information_disclosure",
    "CWE-16": "misconfiguration",
    "CWE-693": "misconfiguration",
    "CWE-1022": "misconfiguration",
    "CWE-345": "misconfiguration",
    "CWE-35": "crypto",
    "CWE-327": "crypto",
    "CWE-756": "misconfiguration",
}
# class aliases so GT and findings converge on one vocabulary
CLASS_ALIASES = {
    "injection": "sql_injection",  # only when SQL tokens also present
    "bola": "idor",
    "authbypass": "broken_auth",
    "jwt": "broken_auth",
    "secret_leak": "information_disclosure",
    "data_exposure": "information_disclosure",
    "info_disclosure": "information_disclosure",
    "disclosure": "information_disclosure",
    "lfi": "file_inclusion",
    "rce": "command_injection",
}

_TITLE_STOP = {"in", "the", "a", "an", "via", "of", "to", "and", "with",
               "on", "for", "at", "by", "from", "field", "endpoint",
               "parameter", "param", "app", "page", "url"}


def _norm_cwe(raw: str | None) -> str | None:
    if not raw:
        return None
    digits = re.search(r"(\d+)", str(raw))
    return f"CWE-{digits.group(1)}" if digits else str(raw).strip().upper()


def _finding_class(finding: Finding) -> str | None:
    """Canonical class of a finding: CWE mapping first, then title tokens."""
    cwe = _norm_cwe(finding.cwe)
    if cwe and cwe in CWE_CLASS:
        return CWE_CLASS[cwe]
    tokens = {t for t in re.findall(r"[a-z0-9]+", finding.title.lower())}
    if {"sql", "sqli"} & tokens:
        return "sql_injection"
    if "xss" in tokens or ("cross" in tokens and "site" in tokens):
        return "xss"
    if ("command" in tokens and "injection" in tokens) or "rce" in tokens:
        return "command_injection"
    if "traversal" in tokens or ("directory" in tokens and "traversal" in tokens):
        return "path_traversal"
    if "idor" in tokens or ("insecure" in tokens and "object" in tokens):
        return "idor"
    if "jwt" in tokens:
        return "broken_auth"
    if "upload" in tokens:
        return "file_upload"
    if "ssti" in tokens or ("template" in tokens and "injection" in tokens):
        return "ssti"
    if "ssrf" in tokens:
        return "ssrf"
    if "redirect" in tokens:
        return "open_redirect"
    if "csrf" in tokens:
        return "csrf"
    if "secret" in tokens or ("key" in tokens and "leak" in tokens):
        return "hardcoded_secret"
    if "disclosure" in tokens or "exposure" in tokens or "leak" in tokens:
        return "information_disclosure"
    if "csp" in tokens or "cors" in tokens or "header" in tokens or (
            "content" in tokens and "security" in tokens):
        return "misconfiguration"
    if cwe:  # unknown CWE, keep it raw for exact-compare with GT
        return cwe
    return None


def _gt_class(entry: dict) -> str:
    raw = str(entry.get("class", "")).lower()
    if raw in CWE_CLASS.values() or raw.startswith("cwe-"):
        return CWE_CLASS.get(_norm_cwe(raw), raw)
    return CLASS_ALIASES.get(raw, raw)


def _endpoint_key(raw: str) -> str:
    """SPA-aware endpoint: a fragment route (#/search) IS the route."""
    from urllib.parse import urlsplit

    parts = urlsplit(raw.strip())
    frag = parts.fragment or ""
    if frag.startswith("/"):
        return frag.split("?", 1)[0] or "/"
    return parts.path or "/"


def _endpoints_compatible(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return True  # class-level GT (or url-less finding): endpointagnostic
    na, nb = _endpoint_key(a), _endpoint_key(b)

    def norm(p: str) -> str:
        segments = ("{id}" if seg.isdigit() else seg for seg in p.split("/"))
        return "/".join(segments).rstrip("/").lower() or "/"

    na, nb = norm(na), norm(nb)
    return na == nb or na.startswith(nb + "/") or nb.startswith(na + "/")


@dataclass
class EvalResult:
    gt_name: str
    target: str
    recall: float
    precision: float
    fp_rate: float
    matched_gt: list[str] = field(default_factory=list)
    missed_gt: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    findings_count: int = 0
    gt_count: int = 0

    def row(self) -> dict:
        return {
            "gt": self.gt_name, "target": self.target,
            "findings": self.findings_count, "ground_truth": self.gt_count,
            "recall": round(self.recall, 3), "fp_rate": round(self.fp_rate, 3),
            "matched": self.matched_gt, "missed": self.missed_gt,
            "false_positives": self.false_positives,
        }


def evaluate(report: FindingsReport, gt: dict) -> EvalResult:
    gt_entries = gt["findings"]
    matched: set[str] = set()
    false_positives: list[str] = []
    for f in report.findings:
        f_class = _finding_class(f)
        f_ep = f.url
        hit = None
        for entry in gt_entries:
            if entry["id"] in matched:
                continue
            if _gt_class(entry) == f_class and _endpoints_compatible(
                    f_ep, entry.get("endpoint")):
                hit = entry["id"]
                break
        if hit:
            matched.add(hit)
        else:
            false_positives.append(f.id or f.title)
    recall = len(matched) / len(gt_entries) if gt_entries else 0.0
    precision = (len(report.findings) - len(false_positives)) / len(report.findings) \
        if report.findings else 1.0
    return EvalResult(
        gt_name=gt.get("name", "?"), target=report.target,
        recall=recall, precision=precision, fp_rate=1 - precision,
        matched_gt=sorted(matched),
        missed_gt=sorted(e["id"] for e in gt_entries if e["id"] not in matched),
        false_positives=false_positives,
        findings_count=len(report.findings), gt_count=len(gt_entries),
    )


def load_ground_truth(path: Path) -> dict:
    gt = json.loads(path.read_text(encoding="utf-8"))
    gt.setdefault("name", path.stem)
    return gt


def run_cost(run_dir: Path) -> dict:
    """Cost signals from a run dir: tokens/turns from the transcript's
    scan_end, wall time from config.json started_at -> report mtime."""
    cost = {"tokens": None, "turns": None, "wall_seconds": None, "model": None}
    config = run_dir / "config.json"
    if config.is_file():
        try:
            data = json.loads(config.read_text(encoding="utf-8"))
            cost["model"] = data.get("model")
        except json.JSONDecodeError:
            pass
    scan_end = None
    transcript = run_dir / "transcript.jsonl"
    if transcript.is_file():
        for line in transcript.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "scan_end":
                scan_end = event
    if scan_end:
        cost["tokens"] = scan_end.get("total_tokens")
        cost["turns"] = scan_end.get("turns_used")
    report_md = run_dir / "report.md"
    if config.is_file() and report_md.is_file():
        try:
            from datetime import datetime

            started = json.loads(config.read_text(encoding="utf-8"))["started_at"]
            t0 = datetime.fromisoformat(started)
            t1 = datetime.fromtimestamp(report_md.stat().st_mtime,
                                        tz=t0.tzinfo)
            cost["wall_seconds"] = int((t1 - t0).total_seconds())
        except (KeyError, ValueError, OSError):
            pass
    return cost
