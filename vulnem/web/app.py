"""FastAPI app: web UI over runs/ — browse (Phase W1) + start scans (Phase W2)
+ onboarding wizard (Phase W3).

Renders the runs list, a run page (meta + agent tree + live SSE stream +
findings), and structured report pages; W2 adds a new-scan form, the typed-host
authorization gate, and job pages for scans launched as CLI subprocesses; W3
adds the /setup wizard (doctor checks in the browser, .env model/key editor,
sandbox build + safe demo as tracked jobs) and a setup banner on the runs list.

Heavy deps (fastapi, jinja2) are imported lazily inside :func:`create_app` to
match the CLI's lazy-import style. ``Request`` and ``UploadFile`` are the two
exceptions: with ``from __future__ import annotations`` FastAPI resolves
endpoint annotations against module globals, so closure-local imports would
not be recognized (this is also why form fields are read via
``await request.form()`` instead of ``Form()`` annotations).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from starlette.datastructures import UploadFile
from starlette.requests import Request

from vulnem import providers
from vulnem.config import Settings
from vulnem.ui.state import RunState, StreamItem
from vulnem.web import checks, envfile, jobs, scans, serialize
from vulnem.web.tail import read_complete_lines, run_status

_WEB_DIR = Path(__file__).resolve().parent
POLL_SECONDS = 0.5
CHECKS_TTL_SECONDS = 30.0  # docker ping per page load is slow when Docker is down
FILE_WHITELIST = ("config.json", "findings.json", "report.md", "report.pdf",
                  "findings.sarif", "transcript.jsonl")


@dataclass(slots=True)
class _ChecksCache:
    """Result of the last environment check run, with its wall-clock time."""

    checks: list[checks.Check]
    computed_at: float


def get_checks(app, settings: Settings, force: bool = False) -> list[checks.Check]:
    """Cached :func:`checks.environment_checks` (TTL 30s, per app instance).

    ``app.state.docker_client`` is the test seam for a fake client; leaving it
    unset means the real lazy ``docker.from_env()`` path runs.
    """
    cache = getattr(app.state, "checks_cache", None)
    now = time.time()
    if (cache is not None and not force
            and now - cache.computed_at < CHECKS_TTL_SECONDS):
        return cache.checks
    fresh = checks.environment_checks(
        settings, docker_client=getattr(app.state, "docker_client", None))
    app.state.checks_cache = _ChecksCache(fresh, now)
    return fresh


def _j(obj: object) -> str:
    return json.dumps(obj, default=str, separators=(",", ":"))


def _sse_event(name: str, payload: object) -> str:
    return f"event: {name}\ndata: {_j(payload)}\n\n"


def _resolve_run(settings: Settings, run_id: str) -> Path | None:
    """Validated direct child of runs_dir, or None (bad id / escape attempt)."""
    if not run_id or "/" in run_id or "\\" in run_id or ".." in run_id:
        return None
    runs_root = settings.runs_dir.resolve()
    run_dir = (settings.runs_dir / run_id).resolve()
    if run_dir.parent != runs_root:  # direct child only — no nested escapes
        return None
    return run_dir


def _summary_paragraphs(summary: str) -> list[str]:
    return [p.strip() for p in re.split(r"\n\s*\n", summary.strip()) if p.strip()]


def create_app(settings: Settings, jobs_manager: jobs.JobManager | None = None):
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates

    app = FastAPI(title="VulnEm", docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=str(_WEB_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR / "static")),
              name="static")
    manager = jobs_manager or jobs.JobManager(runs_dir=settings.runs_dir)
    app.state.jobs = manager
    # .env the wizard edits (re-pointed to a tmp path in tests via app.state)
    app.state.env_path = jobs.PROJECT_ROOT / ".env"

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        """Branded 404 page; carries the route's detail when there is one."""
        return templates.TemplateResponse(
            request=request, name="404.html",
            context={"path": request.url.path,
                     "detail": str(getattr(exc, "detail", "") or "")},
            status_code=404)


    # -- runs list -------------------------------------------------------------

    @app.get("/")
    def index(request: Request):
        rows: list[dict] = []
        if settings.runs_dir.is_dir():
            for child in settings.runs_dir.iterdir():
                if not child.is_dir():
                    continue
                summary = serialize.run_summary(child)
                if summary is not None:
                    rows.append(summary)
        rows.sort(key=lambda r: r["id"], reverse=True)  # names are timestamps
        return templates.TemplateResponse(request=request, name="runs.html",
                                          context={
                                              "runs": rows,
                                              "setup_needed": bool(
                                                  checks.critical_failures(
                                                      get_checks(app, settings))),
                                          })

    # -- run page ----------------------------------------------------------------

    @app.get("/runs/{run_id}")
    def run_page(run_id: str, request: Request):
        run_dir = _resolve_run(settings, run_id)
        if run_dir is None or not (run_dir / "transcript.jsonl").is_file():
            # Merged-report dirs have findings but no transcript to replay —
            # send them to the report page instead of a dead end.
            if (run_dir is not None and (run_dir / "findings.json").is_file()):
                from starlette.responses import RedirectResponse

                return RedirectResponse(f"/runs/{run_id}/report", status_code=307)
            raise HTTPException(status_code=404, detail="run not found")
        state = RunState.from_transcript(run_dir / "transcript.jsonl")
        bootstrap = serialize.state_snapshot(state)
        bootstrap["id"] = run_dir.name
        bootstrap["status"] = run_status(run_dir)
        return templates.TemplateResponse(request=request, name="run.html", context={
            "run_id": run_dir.name,
            "bootstrap": bootstrap,
            "events_url": f"/runs/{run_dir.name}/events",
            "report_url": f"/runs/{run_dir.name}/report",
        })

    # -- SSE: live stream ----------------------------------------------------------

    def _event_stream(run_dir: Path):
        transcript = run_dir / "transcript.jsonl"
        state = RunState()
        events, offset = read_complete_lines(transcript, 0)
        state.apply_all(events)
        yield _sse_event("snap", serialize.state_snapshot(state))
        if any(e.get("type") == "scan_end" for e in events):
            yield _sse_event("end", {"status": "done"})
            return
        while True:
            events, offset = read_complete_lines(transcript, offset)
            if events:
                new_items = _apply_and_capture(state, events)
                yield _sse_event("delta",
                                 serialize.state_delta(state, new_items[-200:]))
                if any(e.get("type") == "scan_end" for e in events):
                    yield _sse_event("end", {"status": "done"})
                    return
            time.sleep(POLL_SECONDS)

    @app.get("/runs/{run_id}/events")
    def run_events(run_id: str):
        run_dir = _resolve_run(settings, run_id)
        if run_dir is None or not (run_dir / "transcript.jsonl").is_file():
            raise HTTPException(status_code=404, detail="run not found")
        return StreamingResponse(
            _event_stream(run_dir),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # -- report page ----------------------------------------------------------------

    @app.get("/runs/{run_id}/report")
    def run_report(run_id: str, request: Request):
        from vulnem.report.findings import findings_from_json

        run_dir = _resolve_run(settings, run_id)
        if run_dir is None or not (run_dir / "findings.json").is_file():
            raise HTTPException(status_code=404,
                                detail="scan not finished yet — no findings.json")
        try:
            report = findings_from_json(run_dir / "findings.json")
        except Exception as exc:
            raise HTTPException(status_code=404,
                                detail=f"cannot parse findings.json: {exc}") from exc
        findings = sorted(report.findings, key=lambda f: f.sort_key())
        downloads = [name for name in ("report.md", "findings.json", "findings.sarif",
                                       "report.pdf")
                     if (run_dir / name).is_file()]
        return templates.TemplateResponse(request=request, name="report.html", context={
            "run_id": run_dir.name,
            "report": report,
            "findings": findings,
            "counts": report.counts(),
            "summary_paragraphs": _summary_paragraphs(report.summary),
            "downloads": downloads,
        })

    # -- raw run files (whitelist) -----------------------------------------------------

    @app.get("/runs/{run_id}/file/{name}")
    def run_file(run_id: str, name: str):
        run_dir = _resolve_run(settings, run_id)
        if run_dir is None or name not in FILE_WHITELIST:
            raise HTTPException(status_code=404, detail="file not found")
        path = run_dir / name
        if not path.is_file():
            raise HTTPException(status_code=404, detail="file not found")
        return FileResponse(path)

    # -- screenshots ---------------------------------------------------------------------

    @app.get("/runs/{run_id}/artifacts/{rest:path}")
    def run_artifact(run_id: str, rest: str):
        run_dir = _resolve_run(settings, run_id)
        if run_dir is None or not rest:
            raise HTTPException(status_code=404, detail="artifact not found")
        artifacts_root = (run_dir / "artifacts").resolve()
        path = (artifacts_root / rest).resolve()
        if (not path.is_relative_to(artifacts_root) or not path.is_file()
                or path == artifacts_root):
            raise HTTPException(status_code=404, detail="artifact not found")
        return FileResponse(path, content_disposition_type="inline")

    # -- new scan (Phase W2) ------------------------------------------------------

    def _preset_rows() -> list[dict]:
        hints = {
            "quick": "Fast triage pass — lowest token cost",
            "balanced": "Default depth for most targets",
            "thorough": "Deep dive — longest runtime, highest token use",
        }
        return [{"id": pid, "budget": budget, "hint": hints[pid]}
                for pid, budget in scans.PRESETS.items()]

    def _truthy(value: object) -> bool:
        return str(value or "").strip().lower() in {"on", "true", "1", "yes"}

    def _form_values(raw: dict) -> dict:
        """Template-friendly view of submitted fields (checkboxes as bools)."""
        return {
            "target": raw.get("target", ""),
            "network": raw.get("network", ""),
            "model": raw.get("model", ""),
            "preset": raw.get("preset", "balanced"),
            "budget": raw.get("budget", ""),
            "source_dir": raw.get("source_dir", ""),
            "solo": _truthy(raw.get("solo")),
            "no_proxy": _truthy(raw.get("no_proxy")),
            "creds_path": raw.get("creds_path", ""),
        }

    def _render_scan(request: Request, error: str, raw: dict):
        return templates.TemplateResponse(request=request, name="scan.html", context={
            "error": error, "values": _form_values(raw), "presets": _preset_rows(),
            "model_examples": list(getattr(providers.lookup(settings.model),
                                           "examples", ()) or ()),
        })

    def _render_authorize(request: Request, form: scans.ScanForm, error: str = ""):
        values = _form_values({
            "target": form.target, "network": form.network, "model": form.model,
            "preset": form.preset, "budget": form.budget or "",
            "source_dir": form.source_dir,
            "solo": "on" if form.solo else "", "no_proxy": "on" if form.no_proxy else "",
            "creds_path": form.creds_path,
        })
        return templates.TemplateResponse(request=request, name="authorize.html",
                                          context={"error": error,
                                                   "host": scans.gate_host(form.target),
                                                   "values": values})

    def _save_creds_upload(data: bytes) -> Path:
        """Persist an uploaded creds file server-side (never logged or echoed)."""
        uploads = settings.runs_dir / ".uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        path = uploads / f"{uuid.uuid4().hex}-creds.json"
        path.write_bytes(data)
        with contextlib.suppress(OSError):  # chmod is mostly a no-op on Windows
            path.chmod(0o600)
        return path

    def _launch_scan(form: scans.ScanForm):
        # Reached only after the typed-host gate was passed, or when the target
        # is isolated on a Docker network (no gate exists — mirrors the CLI).
        argv = scans.build_argv(form, confirmed=True)
        job = manager.launch(argv, name=f"scan {form.target}", discover_run_dir=True)
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    def _raw_fields(form_data) -> dict:
        return {key: str(value) for key, value in form_data.multi_items()
                if key != "creds"}

    @app.get("/scan")
    def scan_page(request: Request):
        return _render_scan(request, "", {})

    @app.post("/scan")
    async def scan_submit(request: Request):
        form_data = await request.form()
        raw = _raw_fields(form_data)
        upload = form_data.get("creds")
        if isinstance(upload, UploadFile) and upload.filename:
            data = await upload.read()
            if data:
                raw["creds_path"] = str(_save_creds_upload(data))
        form, error = scans.parse_scan_form(raw)
        if error:
            # the upload is useless now — remove it rather than orphan a secret
            if raw.get("creds_path"):
                with contextlib.suppress(OSError):
                    Path(raw["creds_path"]).unlink(missing_ok=True)
                raw.pop("creds_path")
            return _render_scan(request, error, raw)
        if scans.requires_gate(form.target, form.network):
            return _render_authorize(request, form)
        return _launch_scan(form)  # isolated network: no gate, straight to launch

    @app.post("/scan/authorize")
    async def scan_authorize(request: Request):
        form_data = await request.form()
        raw = _raw_fields(form_data)
        typed = str(form_data.get("confirm_host") or "")
        form, error = scans.parse_scan_form(raw)  # never trust stale hidden data
        if error:
            if raw.get("creds_path"):  # drop the now-useless uploaded secret
                with contextlib.suppress(OSError):
                    Path(raw["creds_path"]).unlink(missing_ok=True)
                raw.pop("creds_path")
            return _render_scan(request, error, raw)
        if scans.requires_gate(form.target, form.network):
            if not scans.gate_matches(typed, form.target):
                return _render_authorize(
                    request, form,
                    error=f'Typed host does not match "{scans.gate_host(form.target)}" '
                          "— authorization NOT confirmed.")
            return _launch_scan(form)
        return _launch_scan(form)  # isolated after all: no gate needed

    # -- jobs (Phase W2; reused by the W3 setup wizard) ---------------------------

    def _job_or_404(job_id: str) -> jobs.Job:
        job = manager.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job

    @app.get("/jobs/{job_id}")
    def job_page(job_id: str, request: Request):
        job = _job_or_404(job_id)
        return templates.TemplateResponse(request=request, name="job.html", context={
            "job": jobs.to_public_dict(job),
            "status_url": f"/jobs/{job_id}/status.json",
            "stop_url": f"/jobs/{job_id}/stop",
        })

    @app.get("/jobs/{job_id}/status.json")
    def job_status(job_id: str):
        return JSONResponse(jobs.to_public_dict(_job_or_404(job_id)))

    @app.post("/jobs/{job_id}/stop")
    def job_stop(job_id: str):
        if manager.stop(job_id) is None:
            raise HTTPException(status_code=404, detail="job not found")
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    # -- setup wizard (Phase W3) ---------------------------------------------------

    BUILD_JOB_NAME = "build sandbox image"
    DEMO_JOB_NAME = "safe demo scan"

    def _running_job(name: str) -> jobs.Job | None:
        for job in manager.all():
            if job.name == name and job.status not in jobs.TERMINAL_STATUSES:
                return job
        return None

    def _demo_ready(checklist: list[checks.Check]) -> bool:
        by_key = {c.key: c for c in checklist}
        return all(k in by_key and by_key[k].state == "ok"
                   for k in ("docker", "sandbox_image", "provider_key"))

    def _setup_context(checklist: list[checks.Check], error: str = "",
                       saved: bool = False, model_value: str | None = None) -> dict:
        """Template context for /setup — key STATE only, never a key value."""
        by_key = {c.key: c for c in checklist}

        def ok(key: str) -> bool:
            return key in by_key and by_key[key].state == "ok"

        key_var = providers.key_var_for(settings.model) or ""
        keyless = providers.is_keyless(settings.model)
        build_job = _running_job(BUILD_JOB_NAME)
        return {
            "checks": checklist,
            "error": error,
            "saved": saved,
            "model": model_value if model_value is not None else settings.model,
            "key_var": key_var,
            "key_set": bool(key_var and os.environ.get(key_var)),
            "keyless": keyless,
            "provider_map": {row["prefix"]: row for row in providers.picker_rows()},
            "current_prefix": providers.prefix_of(settings.model),
            "api_base_var": "VULNEM_API_BASE",
            "api_base_set": bool(os.environ.get("VULNEM_API_BASE")),
            "sandbox_ok": ok("sandbox_image"),
            "demo_ready": _demo_ready(checklist),
            "build_job_id": build_job.id if build_job else "",
        }

    def _render_setup(request: Request, checklist: list[checks.Check],
                      error: str = "", model_value: str | None = None):
        # model_value re-fills the form after a validation error; the API key
        # input is deliberately NOT re-filled — submitted values never echo.
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context=_setup_context(checklist, error=error,
                                   model_value=model_value))

    @app.get("/setup")
    def setup_page(request: Request, refresh: int = 0, saved: int = 0):
        checklist = get_checks(app, settings, force=bool(refresh))
        return templates.TemplateResponse(
            request=request, name="setup.html",
            context=_setup_context(checklist, saved=bool(saved)))

    @app.post("/setup/refresh")
    def setup_refresh():
        return RedirectResponse("/setup?refresh=1", status_code=303)

    @app.post("/setup/env")
    async def setup_env(request: Request):
        """Save VULNEM_LLM (+ provider key, + optional base URL) to .env.

        Writes ``VULNEM_LLM``, the provider's key var (catalogued or the
        ``<PREFIX>_API_KEY`` convention for unlisted providers), and — when
        filled in — ``VULNEM_API_BASE`` for OpenAI-compatible endpoints
        (ollama, vLLM, LiteLLM proxy, gateways). The key is write-only: it
        lands in .env and os.environ, never in a response, template context,
        or job log.
        """
        form_data = await request.form()
        model = str(form_data.get("model") or "").strip()
        api_key = str(form_data.get("api_key") or "").strip()
        api_base = str(form_data.get("api_base") or "").strip()
        checklist = get_checks(app, settings)  # cached: re-render stays cheap
        if not model or "/" not in model:
            return _render_setup(
                request, checklist, error="Model must be a litellm string with a "
                "provider prefix, e.g. openai/gpt-5.", model_value=model)
        key_var = providers.key_var_for(model)
        updates = {"VULNEM_LLM": model}
        if api_base:
            updates["VULNEM_API_BASE"] = api_base
        if key_var is None:  # catalogued keyless provider (e.g. ollama)
            pass
        elif api_key:
            updates[key_var] = api_key
        elif (key_var not in envfile.read_env(app.state.env_path)
                and not os.environ.get(key_var)):
            return _render_setup(
                request, checklist, error=f"API key required: {key_var} is not "
                "set anywhere yet (leave it blank only to keep an existing "
                "key).", model_value=model)
        envfile.upsert_env(app.state.env_path, updates)
        os.environ.update(updates)  # running checks/jobs see it without restart
        settings.model = model
        return RedirectResponse("/setup?saved=1&refresh=1", status_code=303)

    @app.post("/setup/test-llm")
    async def setup_test_llm(request: Request):
        """On-demand provider round-trip for the Model + API key card.

        Tests the values currently typed in the form — a blank key field
        falls back to the saved key (live env, then .env), a blank base URL
        to the saved ``VULNEM_API_BASE`` — without saving anything. Any
        litellm provider works: catalogued ones resolve their key var,
        unlisted ones the ``<PREFIX>_API_KEY`` convention, catalogued
        keyless providers (ollama) probe with no key. The key is spent on
        the one call only: never persisted, logged, or echoed back.
        ``app.state.llm_ping_fn`` is the test seam, mirroring
        ``app.state.docker_client``.
        """
        try:
            payload = await request.json()
        except Exception:
            payload = None
        if not isinstance(payload, dict):
            return JSONResponse({"ok": False, "error": "Expected a JSON object "
                                 "with model and api_key."}, status_code=400)
        model = str(payload.get("model") or "").strip()
        api_key = str(payload.get("api_key") or "").strip()
        api_base = str(payload.get("api_base") or "").strip()
        if not model or "/" not in model:
            return JSONResponse({"ok": False, "error": "Model must be a litellm "
                                 "string with a provider prefix, e.g. "
                                 "openai/gpt-5."}, status_code=400)
        key_var = providers.key_var_for(model)
        if key_var is not None:  # keyless providers probe without a key
            if not api_key:  # blank field: test the already-saved key instead
                api_key = (os.environ.get(key_var)
                           or envfile.read_env(app.state.env_path).get(key_var)
                           or "")
            if not api_key:
                return JSONResponse({"ok": False, "error": f"No API key for "
                                     f"{key_var} — set it on the Setup page "
                                     "first."}, status_code=400)
        if not api_base:
            api_base = (os.environ.get("VULNEM_API_BASE")
                        or envfile.read_env(app.state.env_path)
                        .get("VULNEM_API_BASE") or "")
        ping = getattr(app.state, "llm_ping_fn", checks.llm_ping)
        result = await asyncio.to_thread(
            ping, model, api_key=api_key or None, api_base=api_base or None)
        return JSONResponse(result)  # probe failure is 200 + ok:false

    @app.post("/setup/build")
    def setup_build():
        running = _running_job(BUILD_JOB_NAME)
        if running is not None:  # never double-launch a minutes-long build
            return RedirectResponse(f"/jobs/{running.id}", status_code=303)
        job = manager.launch(["build"], name=BUILD_JOB_NAME)
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    @app.post("/setup/demo")
    def setup_demo(request: Request):
        checklist = get_checks(app, settings, force=True)
        if not _demo_ready(checklist):  # server-side twin of the disabled button
            by_key = {c.key: c for c in checklist}
            missing = [by_key[k].label if k in by_key else k.replace("_", " ")
                       for k in ("docker", "sandbox_image", "provider_key")
                       if k not in by_key or by_key[k].state != "ok"]
            return templates.TemplateResponse(
                request=request, name="setup.html",
                context=_setup_context(
                    checklist,
                    error="The demo needs Docker reachable, the sandbox image "
                    "built, and the provider API key set — fix first: "
                    f"{', '.join(missing)}."),
                status_code=409)
        job = manager.launch(["demo"], name=DEMO_JOB_NAME, discover_run_dir=True)
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    return app


def _apply_and_capture(state: RunState, events: list[dict]) -> list[StreamItem]:
    """Apply events and return the stream items they appended.

    Each event appends at most one stream item, so a non-growing (full)
    deque still lets us identify the new tail exactly.
    """
    before = len(state.stream)
    state.apply_all(events)
    added = len(state.stream) - before
    if added <= 0:  # deque at maxlen: the batch appended without growing it
        added = min(len(events), len(state.stream))
    return list(state.stream)[-added:] if added > 0 else []
