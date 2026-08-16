"""Pure new-scan form logic for the web UI (no FastAPI imports).

Mirrors the CLI's authorization semantics exactly
(:func:`vulnem.cli._confirm_authorization` / ``_run_scan``):

- ``isolated`` means the scan runs on a dedicated Docker network
  (``settings.docker_network is not None`` — the web's ``network`` field).
- A non-isolated target requires the operator to TYPE THE EXACT HOST before
  the scan may start; the web gate is the equivalent of the CLI's input()
  prompt. ``--yes`` (which skips the CLI gate) may only ever reach the
  subprocess when that gate was passed OR the target is isolated.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from vulnem.scope import Scope, ScopeError

PRESETS = {"quick": 100, "balanced": 200, "thorough": 300}
MIN_BUDGET = 10
MAX_BUDGET = 2000


@dataclass(slots=True)
class ScanForm:
    """One validated new-scan submission (field names match the HTML form)."""

    target: str
    network: str = ""
    model: str = ""
    preset: str = "balanced"
    budget: int | None = None  # overrides the preset when set
    solo: bool = False
    no_proxy: bool = False
    source_dir: str = ""
    creds_path: str = ""  # server-side path of a saved upload


def parse_scan_form(data: Mapping) -> tuple[ScanForm | None, str]:
    """Normalize + validate raw form fields -> ``(form, "")`` or ``(None, error)``.

    ``data`` maps field name -> string (checkboxes arrive as ``"on"``/``"true"``
    when checked and are absent when not).
    """
    target = str(data.get("target") or "").strip()
    if not target:
        return None, "Target URL is required."
    try:
        scope = Scope.from_target(target)
    except ScopeError as exc:
        return None, f"Invalid target: {exc}"
    if any(ch.isspace() for ch in scope.host):
        # urlsplit happily accepts "not a url" as a hostname — it is not one.
        return None, f"Invalid target: {target!r}"

    preset = str(data.get("preset") or "balanced").strip().lower()
    if preset not in PRESETS:
        return None, f"Preset must be one of: {', '.join(PRESETS)}."

    budget: int | None = None
    raw_budget = str(data.get("budget") or "").strip()
    if raw_budget:
        try:
            budget = int(raw_budget)
        except ValueError:
            return None, "Budget override must be a whole number of turns."
        if not MIN_BUDGET <= budget <= MAX_BUDGET:
            return None, f"Budget override must be {MIN_BUDGET}..{MAX_BUDGET} turns."

    source_dir = str(data.get("source_dir") or "").strip()
    if source_dir and not Path(source_dir).is_dir():
        return None, f"Source directory not found: {source_dir}"

    creds_path = str(data.get("creds_path") or "").strip()
    if creds_path and not Path(creds_path).is_file():
        return None, "The uploaded credentials file is gone — attach it again."

    form = ScanForm(
        target=target,
        network=str(data.get("network") or "").strip(),
        model=str(data.get("model") or "").strip(),
        preset=preset,
        budget=budget,
        solo=_truthy(data.get("solo")),
        no_proxy=_truthy(data.get("no_proxy")),
        source_dir=source_dir,
        creds_path=creds_path,
    )
    return form, ""


def _truthy(value: object) -> bool:
    return str(value or "").strip().lower() in {"on", "true", "1", "yes"}


def requires_gate(target: str, network: str) -> bool:
    """The typed-host authorization gate is needed iff the scan is NOT isolated.

    Mirrors the CLI: ``isolated = settings.docker_network is not None``.
    """
    try:
        Scope.from_target(target)
    except ScopeError:
        return True  # an unparseable target must never skip the gate
    return not network.strip()


def gate_host(target: str) -> str:
    """The host the operator must type to pass the gate ("" if unparseable)."""
    try:
        return Scope.from_target(target).host
    except ScopeError:
        return ""


def gate_matches(typed: str, target: str) -> bool:
    """Typed confirmation is valid iff it equals the scope host
    (case-insensitive, whitespace-trimmed) — same rule as the CLI's
    ``_confirm_authorization``."""
    host = gate_host(target)
    return bool(host) and typed.strip().lower() == host.lower()


def build_argv(form: ScanForm, *, confirmed: bool) -> list[str]:
    """``vulnem scan`` argv for a validated form.

    ``--yes`` (which would skip the CLI's authorization prompt) is included
    ONLY when the target is isolated (no gate exists — the CLI skips it too)
    or the web gate was passed. When the gate is required but unconfirmed this
    refuses to build anything rather than launch an unauthorized scan.
    """
    gated = requires_gate(form.target, form.network)
    if gated and not confirmed:
        raise PermissionError(
            "refusing to build a scan argv: typed-host authorization gate "
            f"required for {form.target!r} and not confirmed"
        )
    budget = form.budget if form.budget is not None else PRESETS[form.preset]
    argv = ["scan", form.target, "--budget", str(budget)]
    if form.network:
        argv += ["--network", form.network]
    if form.model:
        argv += ["--model", form.model]
    if form.source_dir:
        argv += ["--source", form.source_dir]
    if form.creds_path:
        argv += ["--creds", form.creds_path]
    if form.solo:
        argv.append("--solo")
    if form.no_proxy:
        argv.append("--no-proxy")
    argv.append("--yes")  # gate passed (or isolated): CLI may run unattended
    return argv
