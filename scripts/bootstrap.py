#!/usr/bin/env python
"""VulnEm one-line bootstrap: venv -> install -> doctor -> web wizard.

    python scripts/bootstrap.py

Creates ``.venv`` when missing (reusing an existing one), pip-installs the
tool editable (``.[dev]`` with ``--dev``), runs ``vulnem doctor`` so the
starting state is visible, then launches ``vulnem ui`` — the Setup wizard in
the browser takes over from there (provider, API key, Base URL, sandbox
build, safe demo). API keys are never accepted here: they belong in the
wizard's write-only field, not in shell history. Stdlib only — this runs
before any dependency exists.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _die(message: str) -> None:
    print(f"bootstrap: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def _require_modern_python(executable: str, *, label: str) -> None:
    check = "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
    if subprocess.run([executable, "-c", check]).returncode != 0:
        _die(f"{label} is older than Python 3.11 — install 3.11+ and rerun")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VulnEm bootstrap: venv + install + doctor + web wizard")
    parser.add_argument("--dev", action="store_true",
                        help="install .[dev] (pytest/ruff) instead of the "
                             "plain dependencies")
    parser.add_argument("--no-ui", action="store_true",
                        help="stop after doctor; skip launching the web wizard")
    args = parser.parse_args()

    if not (ROOT / "pyproject.toml").is_file():
        _die("pyproject.toml not found — run me from a VulnEm checkout")
    _require_modern_python(sys.executable, label="the running interpreter")

    venv_dir = ROOT / ".venv"
    venv_python = venv_dir / ("Scripts/python.exe" if sys.platform == "win32"
                              else "bin/python")
    if not venv_python.is_file():
        print("-> creating .venv ...", flush=True)
        try:
            venv.create(venv_dir, with_pip=True)
        except Exception as exc:
            _die(f"could not create .venv ({exc}) — delete the folder and rerun")
    _require_modern_python(str(venv_python), label=".venv python")

    spec = ".[dev]" if args.dev else "."
    print(f"-> pip install -e {spec}", flush=True)
    if subprocess.run([str(venv_python), "-m", "pip", "install", "-e", spec],
                      cwd=ROOT).returncode != 0:
        _die("pip install failed — see the output above")

    print("-> vulnem doctor (missing key/image here just means the wizard "
          "has work to do)", flush=True)
    subprocess.run([str(venv_python), "-m", "vulnem.cli", "doctor"], cwd=ROOT)

    if args.no_ui:
        print(f"\nNext: {venv_python} -m vulnem.cli ui   "
              "(web Setup wizard: model, key, build, demo)", flush=True)
        return 0
    print("\n-> launching the web UI (Ctrl+C to stop) — "
          "finish setup in the browser", flush=True)
    return subprocess.run([str(venv_python), "-m", "vulnem.cli", "ui"],
                          cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
