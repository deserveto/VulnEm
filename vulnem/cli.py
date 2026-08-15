"""VulnEm command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from vulnem import __version__
from vulnem.agent import run_scan_agent
from vulnem.agent.tools import _list_skills
from vulnem.config import Settings
from vulnem.report.findings import FindingsReport, utc_now_iso
from vulnem.sandbox import Sandbox, SandboxError, build_image
from vulnem.scope import Scope, ScopeError

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
JUICE_SHOP_IMAGE = "bkimminich/juice-shop:latest"

SEVERITY_COLORS = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "cyan"}


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

    if settings.model.startswith("openai/") and not os.environ.get("OPENAI_API_KEY"):
        console.print(
            "[yellow]Warning:[/yellow] OPENAI_API_KEY is not set and model is "
            f"{settings.model}. Set it in .env or the environment."
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


def _on_event(event: dict) -> None:
    kind = event.get("type")
    if kind == "assistant_text":
        console.print(f"[dim]{_shorten(event['text'], 500)}[/dim]\n")
    elif kind == "tool_call":
        name = event.get("name", "?")
        args = event.get("args", {})
        if name == "exec_command":
            console.print(f"[cyan]▸ exec[/cyan] [white]{_shorten(args.get('command', ''), 140)}[/white]")
        elif name == "think":
            console.print(f"[cyan]▸ think[/cyan] [dim]{_shorten(args.get('thoughts', ''), 100)}[/dim]")
        elif name == "report_finding":
            sev = str(args.get("severity", "?")).upper()
            color = SEVERITY_COLORS.get(sev, "green")
            console.print(f"[{color}]▸ finding [{sev}][/{color}] {args.get('title', '')}")
        elif name == "read_skill":
            console.print(f"[cyan]▸ skill[/cyan] {args.get('name', '(list)')}")
        elif name == "finish_scan":
            console.print("[green]▸ finish_scan[/green]")
    elif kind == "scan_end":
        console.print(
            f"\n[bold]Scan ended[/bold] ({event.get('stop_reason')}) — "
            f"turns: {event.get('turns_used')}, tokens: {event.get('total_tokens')}, "
            f"findings: {event.get('findings')}"
        )


def _run_scan(settings: Settings, target: str, *, yes: bool) -> int:
    try:
        scope = Scope.from_target(target)
    except ScopeError as exc:
        console.print(f"[red]Invalid target:[/red] {exc}")
        return 2

    isolated = settings.docker_network is not None
    if not isolated and not _confirm_authorization(scope.host, yes=settings.yes or yes):
        console.print("[red]Authorization not confirmed. Aborting.[/red]")
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
                "started_at": utc_now_iso(),
                "vulnem_version": __version__,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    transcript = run_dir / "transcript.jsonl"

    console.print(Panel.fit(
        f"Target: [bold]{scope.target_url}[/bold]\n"
        f"Model:  {settings.model}\n"
        f"Network: {settings.docker_network or '(default — internet reachable)'}\n"
        f"Run dir: {run_dir}",
        title="VulnEm scan", border_style="blue",
    ))

    sandbox = Sandbox(
        image=settings.sandbox_image,
        user=settings.sandbox_user,
        network=settings.docker_network,
    )
    try:
        sandbox.start()
    except SandboxError as exc:
        console.print(f"[red]Sandbox error:[/red] {exc}")
        return 2

    started_at = utc_now_iso()
    try:
        result = run_scan_agent(
            scope=scope,
            settings=settings,
            sandbox=sandbox,
            transcript_path=transcript,
            on_event=_on_event,
        )
    finally:
        sandbox.stop()

    report = FindingsReport(
        target=scope.target_url,
        started_at=started_at,
        finished_at=utc_now_iso(),
        model=settings.model,
        summary=result.summary or "(no summary)",
        findings=result.findings,
    )
    json_path, md_path = report.write(run_dir)

    counts = report.counts()
    parts = [f"{sev}: {n}" for sev, n in counts.items() if n]
    console.print("\n[bold]Findings:[/bold] " + (", ".join(parts) if parts else "none"))
    console.print(f"Report:     {md_path}")
    console.print(f"Findings:   {json_path}")
    console.print(f"Transcript: {transcript}")
    # CI-friendly exit code: non-zero when findings exist.
    return 1 if result.findings else 0


def _run_demo(settings: Settings) -> int:
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
        return _run_scan(settings, target_url, yes=True)
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
    if args.yes:
        settings.yes = True
    return _run_scan(settings, args.target, yes=args.yes)


def cmd_demo(args: argparse.Namespace) -> int:
    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    if args.model:
        settings.model = args.model
    if args.max_turns:
        settings.max_turns = args.max_turns
    return _run_demo(settings)


def cmd_skills(_args: argparse.Namespace) -> int:
    settings = _resolve_paths(Settings.load(project_root=PROJECT_ROOT))
    packs = _list_skills(settings.skills_dir)
    if not packs:
        console.print(f"No skills found in {settings.skills_dir}")
        return 1
    for p in packs:
        console.print(f"[cyan]{p['name']}[/cyan] — {p['description']}")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
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
    except Exception as exc:
        ok = False
        console.print(f"  [red]✗[/red] Docker not reachable: {exc}")

    console.print(f"  model: {settings.model}")
    provider = settings.model.split("/", 1)[0]
    key_var = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "groq": "GROQ_API_KEY",
    }.get(provider)
    if key_var:
        if os.environ.get(key_var):
            console.print(f"  [green]✓[/green] {key_var} is set")
        else:
            ok = False
            console.print(f"  [yellow]![/yellow] {key_var} is NOT set")
    else:
        console.print("  (custom provider — verify its API key yourself)")
    packs = _list_skills(settings.skills_dir)
    console.print(f"  skills: {len(packs)} packs in {settings.skills_dir}")
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

    p_scan = sub.add_parser("scan", help="Scan an authorized target")
    p_scan.add_argument("target", help="Target URL (e.g. http://juice-shop:3000)")
    p_scan.add_argument("--network", help="Attach sandbox to this Docker network (lab isolation)")
    p_scan.add_argument("--model", help="LLM in litellm format (overrides VULNEM_LLM)")
    p_scan.add_argument("--max-turns", type=int, help="Agent turn cap (default 60)")
    p_scan.add_argument("--yes", action="store_true",
                        help="Skip authorization confirmation (CI / owned assets)")
    p_scan.set_defaults(func=cmd_scan)

    p_demo = sub.add_parser("demo", help="One-command lab: Juice Shop + full scan")
    p_demo.add_argument("--model", help="LLM in litellm format")
    p_demo.add_argument("--max-turns", type=int)
    p_demo.set_defaults(func=cmd_demo)

    p_skills = sub.add_parser("skills", help="List skill packs")
    p_skills.set_defaults(func=cmd_skills)

    p_doctor = sub.add_parser("doctor", help="Check environment readiness")
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
        console.print("\n[yellow]Interrupted.[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
