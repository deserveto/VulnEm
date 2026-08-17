"""VulnEm command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from rich.console import Console
from rich.panel import Panel

from vulnem import __version__
from vulnem.agent.tools import _list_skills
from vulnem.config import Settings
from vulnem.report.findings import FindingsReport, utc_now_iso
from vulnem.sandbox import Sandbox, SandboxError, build_image
from vulnem.scan import load_resume_state, read_run_config, run_scan
from vulnem.scope import Scope, ScopeError

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
JUICE_SHOP_IMAGE = "bkimminich/juice-shop:latest"

SEVERITY_COLORS = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "cyan"}
STATUS_COLORS = {
    "running": "green", "waiting": "yellow", "completed": "bright_green",
    "stopped": "cyan", "crashed": "red", "failed": "red",
}


def _resolve_paths(settings: Settings) -> Settings:
    """Anchor relative paths (skills/, runs/) to the project root, not CWD."""
    if not settings.skills_dir.is_absolute():
        candidate = PROJECT_ROOT / settings.skills_dir
        if not settings.skills_dir.exists() or (candidate.exists() and settings.skills_dir.resolve() != candidate.resolve()):
            settings.skills_dir = candidate
    if not settings.runs_dir.is_absolute():
        settings.runs_dir = PROJECT_ROOT / settings.runs_dir
    return settings


def _check_model_ready(settings: Settings) -> None:
    import os

    from vulnem import providers

    key_var = providers.key_var_for(settings.model)
    if key_var and not os.environ.get(key_var):
        console.print(
            "[yellow]Warning:[/yellow] "
            f"{key_var} is not set and model is {settings.model}. "
            "Set it in .env or the environment."
        )


def _confirm_authorization(host: str, *, yes: bool) -> bool:
    if yes:
        return True
    console.print(
        Panel.fit(
            f"Target [bold]{host}[/bold] is reachable from outside an isolated lab "
            "network.\nAutomated testing without written permission is illegal in "
            "most jurisdictions.",
            title="Authorization required",
            border_style="red",
        )
    )
    try:
        answer = input(f'Type the host "{host}" to confirm you are authorized to test it: ')
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() == host.lower()


def _new_run_dir(settings: Settings, host: str) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    run_dir = settings.runs_dir / f"{stamp}-{host}-{uuid.uuid4().hex[:4]}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def _shorten(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _agent_tag(event: dict) -> str:
    ctx = event.get("agent_ctx") or {}
    name = ctx.get("name")
    if not name:
        return ""
    role = ctx.get("role", "")
    color = "magenta" if role == "root" else ("blue" if role == "solo" else "cyan")
    return f"[{color}][{name}][/{color}] "


def _on_event(event: dict) -> None:
    kind = event.get("type")
    tag = _agent_tag(event)
    if kind == "assistant_text":
        console.print(f"{tag}[dim]{_shorten(event['text'], 400)}[/dim]\n")
    elif kind == "tool_call":
        name = event.get("name", "?")
        args = event.get("args", {})
        if name == "exec_command":
            console.print(f"{tag}[cyan]▸ exec[/cyan] [white]{_shorten(args.get('command', ''), 130)}[/white]")
        elif name == "think":
            console.print(f"{tag}[cyan]▸ think[/cyan] [dim]{_shorten(args.get('thoughts', ''), 90)}[/dim]")
        elif name == "report_finding":
            sev = str(args.get("severity", "?")).upper()
            color = SEVERITY_COLORS.get(sev, "green")
            console.print(f"{tag}[{color}]▸ finding [{sev}][/{color}] {args.get('title', '')}")
        elif name == "read_skill":
            console.print(f"{tag}[cyan]▸ skill[/cyan] {args.get('name', '(list)')}")
        elif name.startswith("browser_"):
            detail = args.get("url") or args.get("selector") or args.get("expression") or ""
            console.print(f"{tag}[magenta]▸ {name.replace('browser_', 'browser.')}"f"[/magenta] [white]{_shorten(str(detail), 100)}[/white]")
        elif name in {"list_requests", "view_request", "repeat_request", "view_sitemap"}:
            console.print(f"{tag}[magenta]▸ {name}[/magenta] "
                          f"{args.get('id', args.get('q', ''))}")
        elif name == "create_agent":
            console.print(f"{tag}[green]▸ create_agent[/green] {args.get('name', '?')} — {_shorten(args.get('objective', ''), 110)}")
        elif name == "wait_for_agents":
            console.print(f"{tag}[yellow]▸ wait_for_agents[/yellow] {args.get('agent_ids') or '(all children)'}")
        elif name in {"finish_scan", "agent_finish"}:
            console.print(f"{tag}[green]▸ {name}[/green]")
        else:
            console.print(f"{tag}[cyan]▸ {name}[/cyan]")
    elif kind == "agent_created":
        console.print(f"[green]+ agent[/green] {event.get('agent')} ({event.get('agent_id')}) spawned by {event.get('parent_id', 'operator')}")
    elif kind == "agent_status":
        to = str(event.get("to", "?"))
        color = STATUS_COLORS.get(to, "white")
        console.print(f"[{color}]{event.get('agent')} -> {to}[/{color}]" +
                      (f" [dim]({event.get('reason')})[/dim]" if event.get("reason") else ""))
    elif kind == "agent_message":
        console.print(f"[dim]msg {event.get('from')} -> {event.get('to')}: {_shorten(event.get('preview', ''), 100)}[/dim]")
    elif kind == "screenshot":
        console.print(f"{tag}[magenta]▣ screenshot[/magenta] {event.get('artifact')} ({event.get('bytes', 0)} bytes)")
    elif kind == "scope_blocked":
        console.print(f"[red]✗ SCOPE BLOCK ({event.get('layer')})[/red] "
                      f"{event.get('method', '')} {event.get('host') or event.get('url', '')}")
    elif kind == "auth_established":
        state = "ok" if event.get("ok") else "FAILED"
        console.print(f"[blue]◉ auth session[/blue] {state} via {event.get('method')} "
                      f"(cookies: {', '.join(event.get('cookie_names') or []) or 'none'})")
    elif kind == "source_map_generated":
        console.print(f"[dim]source map → {event.get('path')} "
                      f"({event.get('bytes', 0)} bytes)[/dim]")
    elif kind == "coverage_report":
        console.print(f"[green]▸ coverage[/green] checklist filed: "
                      f"{len(event.get('rows') or [])} row(s)")
    elif kind == "proxy_started":
        console.print(f"[dim]proxy sidecar {event.get('sidecar')} up "
                      f"(scope: {', '.join(event.get('scope_hosts') or [])})[/dim]")
    elif kind == "scan_end":
        console.print(
            f"\n[bold]Scan ended[/bold] ({event.get('stop_reason')}) — "
            f"turns: {event.get('turns_used')}, tokens: {event.get('total_tokens')}, "
            f"findings: {event.get('findings')}"
        )


def _load_coverage_rows(run_dir: Path) -> list[dict]:
    """Coverage rows root filed via report_coverage (coverage.json); [] if none."""
    try:
        data = json.loads((run_dir / "coverage.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = data.get("rows")
    return rows if isinstance(rows, list) else []


def _write_report(run_dir: Path, settings: Settings, scope: Scope,
                  started_at: str, result) -> FindingsReport:
    report = FindingsReport(
        target=scope.target_url,
        started_at=started_at,
        finished_at=utc_now_iso(),
        model=settings.model,
        summary=result.summary or "(no summary)",
        findings=result.findings,
        coverage=_load_coverage_rows(run_dir),
    )
    report.write(run_dir)
    _export_machine_reports(run_dir, report)
    counts = report.counts()
    parts = [f"{sev}: {n}" for sev, n in counts.items() if n]
    console.print("\n[bold]Findings:[/bold] " + (", ".join(parts) if parts else "none"))
    console.print(f"Report:     {run_dir / 'report.md'}")
    console.print(f"Findings:   {run_dir / 'findings.json'}")
    console.print(f"SARIF:      {run_dir / 'findings.sarif'}")
    console.print(f"PDF:        {run_dir / 'report.pdf'}")
    console.print(f"Transcript: {run_dir / 'transcript.jsonl'}")
    return report


def _export_machine_reports(run_dir: Path, report: FindingsReport | None = None) -> None:
    """Write findings.sarif + report.pdf for a run dir (idempotent)."""
    from vulnem.report.findings import findings_from_json
    from vulnem.report.pdf import report_to_pdf
    from vulnem.report.sarif import write_sarif

    if report is None:
        report = findings_from_json(run_dir / "findings.json")
    write_sarif(report, run_dir)
    report_to_pdf(report, run_dir / "report.pdf")


def cmd_report(args: argparse.Namespace) -> int:
    if args.merge:
        return _run_merge(args)
    if not args.run_dir:
        console.print("[red]report needs a run directory[/red] "
                      "(or several after --merge)")
        return 2
    run_dir = Path(args.run_dir).resolve()
    if not (run_dir / "findings.json").is_file():
        console.print(f"[red]No findings.json in {run_dir}[/red] "
                      "(expected a completed runs/<id> directory)")
        return 2
    from vulnem.report.findings import findings_from_json

    try:
        report = findings_from_json(run_dir / "findings.json")
        report.write(run_dir)  # report.md (fresh summary rendering)
        _export_machine_reports(run_dir, report)
    except Exception as exc:
        console.print(f"[red]Report export failed:[/red] {exc}")
        return 2
    counts = report.counts()
    parts = [f"{sev}: {n}" for sev, n in counts.items() if n]
    console.print(f"Re-exported for [bold]{report.target}[/bold] — findings: "
                  + (", ".join(parts) if parts else "none"))
    console.print(f"  {run_dir / 'report.md'}")
    console.print(f"  {run_dir / 'findings.sarif'}")
    console.print(f"  {run_dir / 'report.pdf'}")
    return 0


def _merged_dir_name(target: str) -> str:
    host = (urlsplit(target).hostname if "://" in target else target) or "target"
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", host).strip("-.")
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{safe or 'target'}-merged-{uuid.uuid4().hex[:4]}"


def _run_merge(args: argparse.Namespace) -> int:
    """Consolidate several completed runs of one target into a single report."""
    from vulnem.report.findings import findings_from_json
    from vulnem.report.merge import MergeError, merge_reports

    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    sources: list[tuple[str, FindingsReport]] = []
    for raw in args.merge:
        run_dir = Path(raw).resolve()
        if not (run_dir / "findings.json").is_file():
            console.print(f"[red]No findings.json in {run_dir}[/red] "
                          "(expected completed runs/<id> directories)")
            return 2
        try:
            sources.append((run_dir.name, findings_from_json(run_dir / "findings.json")))
        except Exception as exc:
            console.print(f"[red]Cannot read findings from {run_dir}:[/red] {exc}")
            return 2
    try:
        report, stats = merge_reports(sources)
    except MergeError as exc:
        console.print(f"[red]Merge refused:[/red] {exc}")
        return 2

    out_dir = (Path(args.out).resolve() if args.out
               else settings.runs_dir / _merged_dir_name(report.target))
    config = {
        "target": report.target,
        "model": report.model,
        "merged": True,
        "sources": [run_id for run_id, _ in sources],
        "started_at": utc_now_iso(),
        "vulnem_version": __version__,
    }
    try:
        report.write(out_dir)
        _export_machine_reports(out_dir, report)
        (out_dir / "config.json").write_text(json.dumps(config, indent=2),
                                             encoding="utf-8")
    except Exception as exc:
        console.print(f"[red]Merged report export failed:[/red] {exc}")
        return 2

    counts = report.counts()
    parts = [f"{sev}: {n}" for sev, n in counts.items() if n]
    console.print(f"Merged [bold]{len(sources)} run(s)[/bold] of "
                  f"[bold]{report.target}[/bold] — {stats['raw']} raw → "
                  f"{stats['unique']} unique "
                  f"({stats['duplicates']} duplicate(s) collapsed): "
                  + (", ".join(parts) if parts else "none"))
    for run_id, n in stats["per_run"].items():
        console.print(f"  [dim]{run_id}: {n} finding(s)[/dim]")
    for name in ("report.md", "findings.json", "findings.sarif", "report.pdf"):
        console.print(f"  {out_dir / name}")
    return 0


def _run_scan(settings: Settings, target: str, *, yes: bool, solo: bool = False,
              budget: int | None = None, creds_path: str | None = None,
              no_proxy: bool = False, ci: bool = False, fail_on: str = "info",
              scope_mode: str = "full", diff_file: str | None = None,
              source_dir: str | None = None) -> int:
    import asyncio as _aio

    from vulnem.auth import CredsConfig, CredsError
    from vulnem.proxy.manager import ProxyError, ProxyManager

    try:
        scope = Scope.from_target(target)
    except ScopeError as exc:
        console.print(f"[red]Invalid target:[/red] {exc}")
        return 2

    isolated = settings.docker_network is not None
    if ci:
        settings.yes = True
    if not isolated and not _confirm_authorization(scope.host, yes=settings.yes or yes):
        console.print("[red]Authorization not confirmed. Aborting.[/red]")
        return 2

    focus_text: str | None = None
    if scope_mode == "diff":
        from vulnem.diffs import load_focus

        focus = load_focus(diff_file=diff_file,
                           source_dir=Path(source_dir) if source_dir else None)
        if focus is None or focus.is_empty():
            console.print("[yellow]--scope-mode diff: no usable diff found "
                          "(--diff-file or a git repo via --source) — running a "
                          "full scan instead.[/yellow]")
        else:
            from vulnem.diffs import focus_directive

            focus_text = focus_directive(focus)
            console.print(f"[cyan]Diff focus:[/cyan] {len(focus.files)} files, "
                          f"{len(focus.endpoints)} endpoints extracted")

    creds: CredsConfig | None = None
    if creds_path:
        try:
            creds = CredsConfig.load(creds_path)
        except CredsError as exc:
            console.print(f"[red]Credentials file error:[/red] {exc}")
            return 2

    proxy: ProxyManager | None = None
    if no_proxy:
        console.print("[yellow]Proxy disabled (--no-proxy): network-layer scope "
                      "enforcement and traffic capture are OFF. The prompt scope "
                      "and (for labs) the internal network remain.[/yellow]")
    else:
        proxy = ProxyManager(scope=scope, network=settings.docker_network)
        try:
            proxy.start()
        except ProxyError as exc:
            console.print(f"[red]Proxy sidecar error:[/red] {exc}")
            return 2

    _check_model_ready(settings)
    run_dir = _new_run_dir(settings, scope.host)
    (run_dir / "config.json").write_text(
        json.dumps(
            {
                "target": scope.target_url,
                "model": settings.model,
                "network": settings.docker_network,
                "max_turns": settings.max_turns,
                "scan_budget_turns": budget,
                "solo": solo,
                "proxy": proxy is not None,
                "creds": creds_path,
                "ci": ci,
                "fail_on": fail_on if ci else None,
                "scope_mode": scope_mode,
                "source": source_dir,
                "started_at": utc_now_iso(),
                "vulnem_version": __version__,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    mode = "solo agent" if solo else "root + specialists (graph)"
    console.print(Panel.fit(
        f"Target: [bold]{scope.target_url}[/bold]\n"
        f"Model:  {settings.model}\n"
        f"Mode:   {mode}\n"
        f"Network: {settings.docker_network or '(default — internet reachable)'}\n"
        f"Proxy:  {proxy.name if proxy else 'disabled'}\n"
        f"Auth:   {'credentials file → session established pre-scan' if creds else 'unauthenticated'}\n"
        + (f"Source: {source_dir} (white-box)\n" if source_dir else "")
        + (f"Scope:  diff-focused ({scope_mode})\n" if focus_text else "")
        + (f"CI:     headless, fail-on={fail_on}\n" if ci else "")
        + f"Run dir: {run_dir}",
        title="VulnEm scan", border_style="blue",
    ))

    sandbox = Sandbox(
        image=settings.sandbox_image,
        user=settings.sandbox_user,
        network=settings.docker_network,
        proxy_url=proxy.sandbox_proxy_url if proxy else None,
        source_dir=source_dir,
    )
    try:
        sandbox.start()
    except SandboxError as exc:
        console.print(f"[red]Sandbox error:[/red] {exc}")
        if proxy is not None:
            proxy.stop()
        return 2

    started_at = utc_now_iso()
    try:
        result = _aio.run(run_scan(
            scope=scope, settings=settings, sandbox=sandbox, run_dir=run_dir,
            solo=solo, on_event=None if ci else _on_event, budget_turns=budget,
            proxy=proxy, creds=creds, focus=focus_text,
        ))
    finally:
        sandbox.stop()
        if proxy is not None:
            proxy.stop()

    report = _write_report(run_dir, settings, scope, started_at, result)
    from vulnem.ci import ci_exit_code, result_line

    code = ci_exit_code(result.findings, fail_on)
    if ci:
        console.print(result_line(report, fail_on=fail_on, exit_code=code))
    return code


def _run_demo(settings: Settings, *, solo: bool = False, budget: int | None = None,
              creds_path: str | None = None, no_proxy: bool = False) -> int:
    """Spin up an isolated Juice Shop lab, scan it, tear it down."""
    import docker

    console.print("[bold]Setting up isolated lab:[/bold] OWASP Juice Shop "
                  "(internal network — sandbox has no internet access)")
    client = docker.from_env()
    network = None
    juice = None
    net_name = f"vulnem-demo-{uuid.uuid4().hex[:6]}"
    # The target's DNS name on the lab network is its container name
    # (docker-py silently drops network aliases, so we rely on name-based DNS).
    shop_name = f"{net_name}-juice-shop"
    target_url = f"http://{shop_name}:3000"
    try:
        network = client.networks.create(net_name, driver="bridge", internal=True)
        console.print(f"  network created: {net_name} (internal)")
        console.print(f"  pulling {JUICE_SHOP_IMAGE} ...")
        client.images.pull(JUICE_SHOP_IMAGE)
        juice = client.containers.run(
            JUICE_SHOP_IMAGE,
            name=shop_name,
            network=net_name,
            detach=True,
        )
        console.print(f"  juice-shop started ({target_url})")

        probe = Sandbox(image=settings.sandbox_image, user=settings.sandbox_user, network=net_name)
        probe.start()
        try:
            console.print("  waiting for target to answer ...")
            if not probe.wait_for_http(target_url, attempts=60, delay=2.0):
                console.print("[red]Juice Shop did not become reachable in time.[/red]")
                return 2
        finally:
            probe.stop()
        console.print("  target is up. starting scan.\n")

        settings.docker_network = net_name
        return _run_scan(settings, target_url, yes=True, solo=solo, budget=budget,
                         creds_path=creds_path, no_proxy=no_proxy)
    except SandboxError as exc:
        console.print(f"[red]Sandbox error:[/red] {exc}")
        return 2
    except docker.errors.DockerException as exc:
        console.print(f"[red]Docker error during lab setup:[/red] {exc}")
        return 2
    except Exception as exc:
        console.print(f"[red]Lab setup failed:[/red] {exc}")
        return 2
    finally:
        if juice is not None:
            juice.remove(force=True, v=True)
        if network is not None:
            with contextlib.suppress(Exception):
                network.remove()
        console.print(f"[dim]Lab torn down (network {net_name}).[/dim]")


def _run_resume(settings: Settings, run_dir: Path, *, model: str | None = None,
                extend_turns: int | None = None) -> int:
    import asyncio as _aio

    from vulnem.auth import CredsConfig, CredsError
    from vulnem.proxy.manager import ProxyError, ProxyManager

    try:
        state = load_resume_state(run_dir)
        config = read_run_config(run_dir)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Cannot resume:[/red] {exc}")
        return 2

    try:
        scope = Scope.from_target(config["target"])
    except (KeyError, ScopeError) as exc:
        console.print(f"[red]Bad target in run config:[/red] {exc}")
        return 2

    if model:
        settings.model = model
    settings.docker_network = config.get("network")
    if extend_turns:
        budget = state.get("budget", {})
        budget["max_turns"] = (budget.get("max_turns") or 0) + extend_turns
        console.print(f"[green]Scan budget extended by {extend_turns} turns.[/green]")

    creds = None
    if config.get("creds"):
        try:
            creds = CredsConfig.load(config["creds"])
        except CredsError as exc:
            console.print(f"[yellow]Credentials file no longer loadable "
                          f"(continuing unauthenticated):[/yellow] {exc}")

    proxy = None
    if config.get("proxy", False):
        proxy = ProxyManager(scope=scope, network=settings.docker_network)
        try:
            proxy.start()
        except ProxyError as exc:
            console.print(f"[red]Proxy sidecar error:[/red] {exc}")
            return 2

    console.print(Panel.fit(
        f"Resuming: [bold]{scope.target_url}[/bold]\n"
        f"Run dir:  {run_dir}\n"
        f"Model:    {settings.model}\n"
        f"Proxy:    {proxy.name if proxy else 'disabled'}",
        title="VulnEm resume", border_style="blue",
    ))

    sandbox = Sandbox(
        image=settings.sandbox_image,
        user=settings.sandbox_user,
        network=settings.docker_network,
        proxy_url=proxy.sandbox_proxy_url if proxy else None,
        source_dir=config.get("source"),  # keep the white-box mount on resume
    )
    try:
        sandbox.start()
    except SandboxError as exc:
        console.print(f"[red]Sandbox error:[/red] {exc} (is the target's network still up?)")
        if proxy is not None:
            proxy.stop()
        return 2

    try:
        result = _aio.run(run_scan(
            scope=scope, settings=settings, sandbox=sandbox, run_dir=run_dir,
            solo=config.get("solo", False), on_event=_on_event,
            resume_state=state, proxy=proxy, creds=creds,
        ))
    finally:
        sandbox.stop()
        if proxy is not None:
            proxy.stop()

    started_at = config.get("started_at", utc_now_iso())
    _write_report(run_dir, settings, scope, started_at, result)
    return 1 if result.findings else 0


def cmd_build(args: argparse.Namespace) -> int:
    build_image(dockerfile_dir=PROJECT_ROOT / "containers", tag=args.tag)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    if args.network:
        settings.docker_network = args.network
    if args.model:
        settings.model = args.model
    if args.max_turns:
        settings.max_turns = args.max_turns
    if args.max_agents:
        settings.max_agents = args.max_agents
    if args.yes:
        settings.yes = True
    return _run_scan(settings, args.target, yes=args.yes,
                     solo=args.solo, budget=args.budget,
                     creds_path=args.creds, no_proxy=args.no_proxy,
                     ci=args.ci, fail_on=args.fail_on,
                     scope_mode=args.scope_mode, diff_file=args.diff_file,
                     source_dir=args.source)


def cmd_demo(args: argparse.Namespace) -> int:
    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    if args.model:
        settings.model = args.model
    if args.max_turns:
        settings.max_turns = args.max_turns
    if args.max_agents:
        settings.max_agents = args.max_agents
    return _run_demo(settings, solo=args.solo, budget=args.budget,
                     creds_path=args.creds, no_proxy=args.no_proxy)


def cmd_resume(args: argparse.Namespace) -> int:
    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    return _run_resume(settings, Path(args.run_dir).resolve(),
                       model=args.model, extend_turns=args.extend_turns)


def cmd_tui(args: argparse.Namespace) -> int:
    from vulnem.ui.tui import run_tui

    run_dir = Path(args.run_dir).resolve()
    if not (run_dir / "transcript.jsonl").is_file():
        console.print(f"[red]No transcript.jsonl in {run_dir}[/red] "
                      "(expected a runs/<id> directory)")
        return 2
    with contextlib.suppress(KeyboardInterrupt):
        run_tui(run_dir, speed=args.speed, follow=args.follow)
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    import threading
    import webbrowser

    import uvicorn

    from vulnem.web.app import create_app

    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    app = create_app(settings)
    url = f"http://{args.host}:{args.port}"
    console.print(f"[cyan]VulnEm web UI:[/cyan] {url} "
                  "(read-only — browse runs, watch scans live, read reports)")
    if not args.no_open:
        threading.Timer(1.0, webbrowser.open, args=[url]).start()
    with contextlib.suppress(KeyboardInterrupt):
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_skills(_args: argparse.Namespace) -> int:
    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    packs = _list_skills(settings.skills_dir)
    if not packs:
        console.print(f"No skills found in {settings.skills_dir}")
        return 1
    for p in packs:
        console.print(f"[cyan]{p['name']}[/cyan] — {p['description']}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    import os

    ok = True
    console.print(f"vulnem {__version__} — environment check")
    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    try:
        import docker

        client = docker.from_env()
        client.ping()
        console.print("  [green]✓[/green] Docker daemon reachable")
        try:
            client.images.get(settings.sandbox_image)
            console.print(f"  [green]✓[/green] Sandbox image {settings.sandbox_image} present")
        except docker.errors.ImageNotFound:
            ok = False
            console.print("  [yellow]![/yellow] Sandbox image missing — run `vulnem build`")
        try:
            from vulnem.proxy.manager import SIDECAR_IMAGE

            client.images.get(SIDECAR_IMAGE)
            console.print(f"  [green]✓[/green] Proxy sidecar image {SIDECAR_IMAGE} present")
        except docker.errors.ImageNotFound:
            console.print("  [yellow]![/yellow] Proxy sidecar image missing — it will be "
                          "pulled on first use (needs internet once)")
    except Exception as exc:
        ok = False
        console.print(f"  [red]✗[/red] Docker not reachable: {exc}")

    console.print(f"  model: {settings.model}")
    from vulnem import providers

    provider = providers.lookup(settings.model)
    key_var = providers.key_var_for(settings.model)
    if provider is not None and key_var is None:
        console.print(f"  [green]✓[/green] {provider.label} needs no API key")
    elif key_var:
        if os.environ.get(key_var):
            console.print(f"  [green]✓[/green] {key_var} is set")
        elif provider is None:
            console.print(f"  [yellow]![/yellow] unlisted provider — set {key_var} "
                          "if it uses the conventional name")
        else:
            ok = False
            console.print(f"  [yellow]![/yellow] {key_var} is NOT set")
    else:
        console.print("  model lacks a provider prefix — expected litellm format "
                      "like openai/gpt-5")
    if getattr(settings, "api_base", None):
        console.print("  API base: VULNEM_API_BASE is set (OpenAI-compatible endpoint)")
    packs = _list_skills(settings.skills_dir)
    console.print(f"  skills: {len(packs)} packs in {settings.skills_dir}")
    if args.ping_llm:
        from vulnem.web.checks import llm_ping

        console.print(f"  pinging {settings.model} (1 token) …")
        result = llm_ping(settings.model,
                          api_base=getattr(settings, "api_base", None))
        if result["ok"]:
            console.print(f"  [green]✓[/green] provider answered — {result['model']} "
                          f"in {result['latency_ms']} ms")
        else:
            ok = False
            console.print(f"  [red]✗[/red] {result['error']}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnem",
        description="VulnEm — autonomous AI pentest agent for authorized testing.",
    )
    parser.add_argument("--version", action="version", version=f"vulnem {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="Build the sandbox Docker image")
    p_build.add_argument("--tag", default=None, help="Image tag (default: vulnem-sandbox:latest)")
    p_build.set_defaults(func=cmd_build)

    p_scan = sub.add_parser("scan", help="Scan an authorized target (multi-agent graph)")
    p_scan.add_argument("target", help="Target URL (e.g. http://juice-shop:3000)")
    p_scan.add_argument("--network", help="Attach sandbox to this Docker network (lab isolation)")
    p_scan.add_argument("--model", help="LLM in litellm format (overrides VULNEM_LLM)")
    p_scan.add_argument("--max-turns", type=int, help="Turn cap per agent (default 60)")
    p_scan.add_argument("--budget", type=int,
                        help="Scan-wide turn budget across all agents (default 4x max-turns)")
    p_scan.add_argument("--max-agents", type=int, help="Agent cap for the graph (default 8)")
    p_scan.add_argument("--solo", action="store_true",
                        help="Phase 1 single-agent mode (no coordinator graph)")
    p_scan.add_argument("--creds", metavar="FILE",
                        help="Credentials JSON for an authenticated scan (login URL + "
                             "secrets; values never enter agent prompts)")
    p_scan.add_argument("--no-proxy", action="store_true",
                        help="Disable the mitmproxy sidecar (drops network-layer scope "
                             "enforcement and traffic capture)")
    p_scan.add_argument("--ci", action="store_true",
                        help="Headless CI mode: no prompts, no live event stream, "
                             "one VULNEM_RESULT summary line, exit 1 on findings")
    p_scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                        default="info",
                        help="Exit non-zero only for findings at/above this severity "
                             "(default: info — any finding fails)")
    p_scan.add_argument("--scope-mode", choices=["full", "diff"], default="full",
                        help="diff: PR-sized scan focused on files/endpoints from the "
                             "PR diff (prompt-level narrowing; enforcement layers "
                             "are never weakened)")
    p_scan.add_argument("--diff-file", metavar="FILE",
                        help="Unified diff to focus on with --scope-mode diff "
                             "(default: git diff origin/main...HEAD via --source)")
    p_scan.add_argument("--source", metavar="DIR",
                        help="Target source directory — mounted read-only into the "
                             "sandbox for white-box analysis (semgrep + code reading)")
    p_scan.add_argument("--yes", action="store_true",
                        help="Skip authorization confirmation (CI / owned assets)")
    p_scan.set_defaults(func=cmd_scan)

    p_demo = sub.add_parser("demo", help="One-command lab: Juice Shop + full multi-agent scan")
    p_demo.add_argument("--model", help="LLM in litellm format")
    p_demo.add_argument("--max-turns", type=int)
    p_demo.add_argument("--budget", type=int, help="Scan-wide turn budget")
    p_demo.add_argument("--max-agents", type=int)
    p_demo.add_argument("--solo", action="store_true", help="Phase 1 single-agent mode")
    p_demo.add_argument("--creds", metavar="FILE",
                        help="Credentials JSON for an authenticated demo scan")
    p_demo.add_argument("--no-proxy", action="store_true",
                        help="Disable the mitmproxy sidecar")
    p_demo.set_defaults(func=cmd_demo)

    p_resume = sub.add_parser("resume", help="Resume an interrupted scan from its snapshot")
    p_resume.add_argument("run_dir", help="Run directory (e.g. runs/20260816-...-juice-shop-ab12)")
    p_resume.add_argument("--model", help="Override the LLM")
    p_resume.add_argument("--extend-turns", type=int,
                          help="Top up the scan-wide turn budget before resuming")
    p_resume.set_defaults(func=cmd_resume)

    p_report = sub.add_parser(
        "report", help="Re-export SARIF + PDF for a completed run")
    p_report.add_argument("run_dir", nargs="?",
                          help="Run directory (e.g. runs/20260816-...-juice-shop-ab12)")
    p_report.add_argument("--merge", nargs="+", metavar="RUN",
                          help="Consolidate several completed runs of the same "
                               "target into one report (closes the 'one run is "
                               "a sample' gap; re-finds merge with per-run "
                               "attribution)")
    p_report.add_argument("--out", metavar="DIR",
                          help="Output directory for --merge "
                               "(default: runs/<ts>-<host>-merged-<id>)")
    p_report.set_defaults(func=cmd_report)

    p_tui = sub.add_parser("tui", help="Replay/watch a run: agent graph, tool stream, findings")
    p_tui.add_argument("run_dir", help="Run directory (e.g. runs/20260816-...-juice-shop-ab12)")
    p_tui.add_argument("--speed", type=int, default=None,
                       help="Replay speed in events/sec (0 = instant; default: auto)")
    p_tui.add_argument("--follow", action="store_true",
                       help="Keep tailing the transcript after catch-up (live scan)")
    p_tui.set_defaults(func=cmd_tui)

    p_ui = sub.add_parser(
        "ui", help="Open the local web app (browse runs, watch scans live, read reports)")
    p_ui.add_argument("--host", default="127.0.0.1",
                      help="Bind address (default: 127.0.0.1)")
    p_ui.add_argument("--port", type=int, default=8756,
                      help="Port to listen on (default: 8756)")
    p_ui.add_argument("--no-open", action="store_true",
                      help="Do not auto-open the browser")
    p_ui.set_defaults(func=cmd_ui)

    p_skills = sub.add_parser("skills", help="List skill packs")
    p_skills.set_defaults(func=cmd_skills)

    p_doctor = sub.add_parser("doctor", help="Check environment readiness")
    p_doctor.add_argument("--ping-llm", action="store_true",
                          help="Also ping the LLM provider with a 1-token call — "
                               "validates the key and model for real")
    p_doctor.set_defaults(func=cmd_doctor)
    return parser


def _harden_windows_console() -> None:
    """Legacy Windows consoles (cmd.exe codepage 437/936/...) cannot encode
    characters like ▸ and ✓ — replace instead of crashing the scan output."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(errors="replace")


def main(argv: list[str] | None = None) -> int:
    _harden_windows_console()
    args = build_parser().parse_args(argv)
    if getattr(args, "tag", None) is None:
        args.tag = Settings.load(project_root=PROJECT_ROOT).sandbox_image
    try:
        return args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow] "
                      "State was snapshotted — resume with `vulnem resume <run_dir>`.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
