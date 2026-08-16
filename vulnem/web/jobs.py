"""Background job runner for the web UI: subprocesses with streamed logs.

A Job wraps one ``Popen`` (default: ``python -m vulnem.cli <argv>`` — the web
layer always drives the real CLI, never in-process scan code). A daemon reader
thread streams combined stdout/stderr into a bounded log deque, and an optional
watcher thread discovers the run directory the CLI creates under runs/ so the
job page can link straight into the live run view.

Jobs are in-memory only: if the server restarts, running scans survive as
independent processes and their run dirs remain browsable via the runs list —
only the live log stream and the stop button are lost.

Tests (and later phases, e.g. the W3 setup wizard) substitute the command via
``JobManager(cmd_factory=...)`` or ``launch(..., cmd=...)`` instead of the
real CLI.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOG_MAX_LINES = 800
PUBLIC_LOG_TAIL = 200
RUN_DIR_POLL_SECONDS = 0.5
RUN_DIR_EXIT_GRACE_SECONDS = 2.0  # keep polling briefly after the proc exits
STOP_WAIT_SECONDS = 5.0
TERMINAL_STATUSES = ("done", "failed", "stopped")


def _default_cmd(argv: list[str]) -> list[str]:
    return [sys.executable, "-m", "vulnem.cli", *argv]


@dataclass(slots=True)
class Job:
    """One launched subprocess. ``proc`` never leaves this process (it is not
    JSON-serializable) — use :func:`to_public_dict` for anything client-facing."""

    id: str
    name: str
    argv: list[str]  # display form (e.g. "scan http://x --budget 200")
    cmd: list[str] = field(default_factory=list, repr=False)
    status: str = "starting"  # starting|running|done|failed|stopped
    exit_code: int | None = None
    started_at: str = ""
    run_dir: str = ""  # direct child dir NAME under runs_dir once discovered
    log: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_MAX_LINES))
    proc: subprocess.Popen | None = field(default=None, repr=False)


def to_public_dict(job: Job) -> dict:
    """JSON-safe view of a job: no proc handle, log capped to the tail."""
    return {
        "id": job.id,
        "name": job.name,
        "argv": job.argv,
        "status": job.status,
        "exit_code": job.exit_code,
        "started_at": job.started_at,
        "run_dir": job.run_dir,
        "log": list(job.log)[-PUBLIC_LOG_TAIL:],
    }


class JobManager:
    """Launches and tracks subprocess jobs (one instance per app)."""

    def __init__(self, runs_dir: Path | str | None = None,
                 cmd_factory: Callable[[list[str]], list[str]] | None = None) -> None:
        self.runs_dir = Path(runs_dir) if runs_dir is not None else PROJECT_ROOT / "runs"
        self._cmd_factory = cmd_factory or _default_cmd
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()  # guards job status/run_dir/log mutations

    # -- launching -------------------------------------------------------------

    def launch(self, argv: list[str], *, name: str = "",
               cmd: list[str] | None = None,
               discover_run_dir: bool = False) -> Job:
        """Start ``cmd`` (default: the real CLI with ``argv``) and track it.

        ``argv`` is the display form; ``cmd`` is what actually executes — tests
        pass a fake script here (or swap the whole default via ``cmd_factory``).
        """
        job = Job(
            id=uuid.uuid4().hex[:12],
            name=name or " ".join(argv),
            argv=argv,
            cmd=list(cmd) if cmd is not None else self._cmd_factory(list(argv)),
            started_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        started_marker = time.time() - 1.0  # FS mtime granularity slack
        proc = subprocess.Popen(  # cmd is operator-configured (CLI or a test fake)
            job.cmd, cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            env=os.environ,
        )
        job.proc = proc
        with self._lock:
            job.status = "running"
            self._jobs[job.id] = job
        threading.Thread(target=self._read_stream, args=(job,), daemon=True,
                         name=f"job-{job.id}-reader").start()
        if discover_run_dir:
            threading.Thread(target=self._watch_run_dir, args=(job, started_marker),
                             daemon=True, name=f"job-{job.id}-watcher").start()
        return job

    def _read_stream(self, job: Job) -> None:
        """Stream the proc's combined output into job.log; finalize on EOF."""
        proc = job.proc
        assert proc is not None and proc.stdout is not None
        try:
            for line in proc.stdout:
                with self._lock:
                    job.log.append(line.rstrip("\r\n"))
        except OSError:
            pass  # pipe torn down (e.g. process killed) — finalize below
        finally:
            exit_code = proc.wait()
            with self._lock:
                job.exit_code = exit_code
                if job.status not in TERMINAL_STATUSES:
                    job.status = "done" if exit_code == 0 else "failed"

    def _watch_run_dir(self, job: Job, started_marker: float) -> None:
        """Poll runs_dir for a NEW direct child with config.json (first wins).

        Keeps polling a short grace period after the proc exits so a CLI that
        writes config.json right before finishing is still discovered.
        """
        deadline: float | None = None
        while True:
            with self._lock:
                if job.run_dir:
                    return
                proc = job.proc
            if proc is not None and proc.poll() is not None:
                if deadline is None:
                    deadline = time.monotonic() + RUN_DIR_EXIT_GRACE_SECONDS
                elif time.monotonic() > deadline:
                    return
            if self.runs_dir.is_dir():
                for child in self.runs_dir.iterdir():
                    if not child.is_dir():
                        continue
                    try:
                        recent = child.stat().st_mtime >= started_marker
                        has_config = (child / "config.json").is_file()
                    except OSError:
                        continue
                    if recent and has_config:
                        with self._lock:
                            if not job.run_dir:  # first match wins
                                job.run_dir = child.name
                        return
            time.sleep(RUN_DIR_POLL_SECONDS)

    # -- control / queries -------------------------------------------------------

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def all(self) -> list[Job]:
        """Newest-first (insertion order reversed)."""
        return list(reversed(self._jobs.values()))

    def stop(self, job_id: str) -> Job | None:
        """Terminate the job's process; escalate to kill after 5s."""
        job = self._jobs.get(job_id)
        if job is None:
            return None
        proc = job.proc
        with self._lock:
            if job.status in TERMINAL_STATUSES:
                return job  # already finished on its own
            job.status = "stopped"  # claim BEFORE signalling, so the reader
            # thread's done/failed finalize cannot race-override the operator's
            # explicit stop (both check TERMINAL_STATUSES under the lock)
        if proc is not None:
            proc.terminate()  # no-op if the process already exited
            try:
                proc.wait(timeout=STOP_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):  # pragma: no cover
                    proc.wait(timeout=STOP_WAIT_SECONDS)
        with self._lock:
            job.exit_code = proc.returncode
        return job
