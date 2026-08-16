"""Shared test fixtures/paths.

`tests/fixtures/run/` is a committed, compact stand-in for a real runs/<id>
directory (regenerate with scripts/make_test_fixture.py) so the TUI/reports/
evals code paths are covered on any fresh checkout — CI included. The rich
recorded runs under runs/ exist only on dev machines; tests that need them
skip when absent.
"""

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_RUN = Path(__file__).resolve().parent / "fixtures" / "run"
REAL_RUNS = PROJECT_ROOT / "runs"
EA92 = REAL_RUNS / "20260815-195935-juice-shop-ea92"
DVWA_6251 = REAL_RUNS / "20260815-193336-dvwa-6251"

requires_recorded_runs = pytest.mark.skipif(
    not (EA92.is_dir() and DVWA_6251.is_dir()),
    reason="recorded runs/ directories are local-only (fixtures cover CI)",
)
