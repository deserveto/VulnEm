"""Tests for the W2 scan-launching web UI (vulnem/web/scans.py + jobs.py + routes).

No Docker, no LLM, no network: the JobManager runs tiny fake scripts instead of
the real CLI (via ``cmd_factory``), and the app gets a manager pointed at a tmp
runs dir. Deadlines are polled, never slept blind.
"""

from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

import pytest
from conftest import FIXTURE_RUN

from vulnem.config import Settings
from vulnem.web import scans
from vulnem.web.app import create_app
from vulnem.web.jobs import JobManager

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

TARGET = "http://juice-shop:3000"

FAKE_SCAN = """\
import json, sys, time, uuid
from pathlib import Path
runs = Path(sys.argv[1])
d = runs / f"20260816-000000-fake-target-{uuid.uuid4().hex[:4]}"
d.mkdir(parents=True, exist_ok=True)
(d / "config.json").write_text(json.dumps({"target": "http://fake-target:3000"}))
print("fake scan started")
time.sleep(1.0)
print("fake scan done")
"""

FAKE_SLEEPER = """\
import time
print("sleeping", flush=True)
time.sleep(30)
"""


def wait_until(predicate, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture()
def fake_script(tmp_path: Path) -> Path:
    script = tmp_path / "fake_scan.py"
    script.write_text(FAKE_SCAN, encoding="utf-8")
    return script


@pytest.fixture()
def sleeper_script(tmp_path: Path) -> Path:
    script = tmp_path / "fake_sleeper.py"
    script.write_text(FAKE_SLEEPER, encoding="utf-8")
    return script


@pytest.fixture()
def runs_dir(tmp_path: Path) -> Path:
    runs = tmp_path / "runs"
    runs.mkdir()
    return runs


@pytest.fixture()
def manager(runs_dir: Path, fake_script: Path) -> JobManager:
    return JobManager(runs_dir=runs_dir,
                      cmd_factory=lambda argv: [sys.executable, str(fake_script),
                                                str(runs_dir)])


@pytest.fixture()
def client(runs_dir: Path, manager: JobManager) -> TestClient:
    settings = Settings(runs_dir=runs_dir, skills_dir=runs_dir)
    return TestClient(create_app(settings, jobs_manager=manager))


def job_argv(client: TestClient, job_id: str) -> list[str]:
    resp = client.get(f"/jobs/{job_id}/status.json")
    assert resp.status_code == 200
    return resp.json()["argv"]


# -- scans.parse_scan_form -------------------------------------------------------


def test_parse_form_minimal() -> None:
    form, error = scans.parse_scan_form({"target": TARGET})
    assert error == "" and form is not None
    assert form.target == TARGET
    assert form.preset == "balanced"
    assert form.budget is None and not form.solo and not form.no_proxy


def test_parse_form_trims_and_normalizes() -> None:
    form, _ = scans.parse_scan_form({"target": f"  {TARGET} ", "network": " labnet ",
                                     "model": " openai/gpt-5 ", "budget": " 42 ",
                                     "solo": "on", "no_proxy": "true",
                                     "source_dir": "  "})
    assert form is not None
    assert form.target == TARGET and form.network == "labnet"
    assert form.model == "openai/gpt-5" and form.budget == 42
    assert form.solo and form.no_proxy and form.source_dir == ""


def test_parse_form_rejects_bad_target() -> None:
    for bad in ("", "not a url", "ftp://juice-shop:3000"):
        form, error = scans.parse_scan_form({"target": bad})
        assert form is None, bad
        assert "Invalid target" in error or "required" in error, bad


def test_parse_form_rejects_bad_preset() -> None:
    form, error = scans.parse_scan_form({"target": TARGET, "preset": "yolo"})
    assert form is None and "Preset" in error


def test_parse_form_rejects_missing_source_dir(tmp_path: Path) -> None:
    form, error = scans.parse_scan_form({"target": TARGET,
                                         "source_dir": str(tmp_path / "nope")})
    assert form is None and "Source directory" in error
    form, _ = scans.parse_scan_form({"target": TARGET, "source_dir": str(tmp_path)})
    assert form is not None


def test_parse_form_rejects_out_of_range_budget() -> None:
    for bad in ("9", "2001", "abc"):
        form, error = scans.parse_scan_form({"target": TARGET, "budget": bad})
        assert form is None and "Budget" in error, bad


# -- gate logic -------------------------------------------------------------------


def test_requires_gate_truth_table() -> None:
    assert scans.requires_gate(TARGET, "") is True          # internet -> gated
    assert scans.requires_gate(TARGET, "   ") is True       # whitespace is empty
    assert scans.requires_gate(TARGET, "vulnem-lab_labnet") is False  # isolated


def test_gate_matches_case_insensitive_and_trimmed() -> None:
    assert scans.gate_matches("juice-shop", TARGET) is True
    assert scans.gate_matches("  JUICE-SHOP  ", TARGET) is True
    assert scans.gate_matches("JUICE-SHOP.example", TARGET) is False
    assert scans.gate_matches(TARGET, TARGET) is False      # full URL is not the host
    assert scans.gate_matches("", TARGET) is False


def test_gate_host_extracts_scope_host() -> None:
    assert scans.gate_host(TARGET) == "juice-shop"


# -- scans.build_argv --------------------------------------------------------------


def test_build_argv_maps_presets_to_budgets() -> None:
    for preset, budget in scans.PRESETS.items():
        form, _ = scans.parse_scan_form({"target": TARGET, "preset": preset})
        argv = scans.build_argv(form, confirmed=True)  # type: ignore[arg-type]
        assert argv[:4] == ["scan", TARGET, "--budget", str(budget)]
        assert "--yes" in argv


def test_build_argv_budget_overrides_preset() -> None:
    form, _ = scans.parse_scan_form({"target": TARGET, "preset": "quick",
                                     "budget": "500"})
    argv = scans.build_argv(form, confirmed=True)  # type: ignore[arg-type]
    assert argv[2:4] == ["--budget", "500"]


def test_build_argv_includes_options_only_when_set(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    creds = tmp_path / "c.json"
    creds.write_text("{}", encoding="utf-8")
    form, _ = scans.parse_scan_form({"target": TARGET})
    argv = scans.build_argv(form, confirmed=True)  # type: ignore[arg-type]
    for absent in ("--network", "--model", "--source", "--creds", "--solo",
                   "--no-proxy"):
        assert absent not in argv
    form, _ = scans.parse_scan_form({"target": TARGET, "network": "labnet",
                                     "model": "m", "source_dir": str(source),
                                     "creds_path": str(creds),
                                     "solo": "on", "no_proxy": "on"})
    argv = scans.build_argv(form, confirmed=True)  # type: ignore[arg-type]
    for pair in (("--network", "labnet"), ("--model", "m"), ("--source", str(source)),
                 ("--creds", str(creds))):
        assert list(pair) in [argv[i:i + 2] for i in range(len(argv) - 1)], pair
    assert "--solo" in argv and "--no-proxy" in argv


def test_build_argv_yes_only_when_authorized() -> None:
    # isolated network: --yes without any web confirmation (matches the CLI)
    form, _ = scans.parse_scan_form({"target": TARGET, "network": "labnet"})
    argv = scans.build_argv(form, confirmed=False)  # type: ignore[arg-type]
    assert "--yes" in argv
    # gated + confirmed: --yes allowed
    form, _ = scans.parse_scan_form({"target": TARGET})
    argv = scans.build_argv(form, confirmed=True)  # type: ignore[arg-type]
    assert "--yes" in argv
    # gated + NOT confirmed: refuse to build anything
    form, _ = scans.parse_scan_form({"target": TARGET})
    with pytest.raises(PermissionError):
        scans.build_argv(form, confirmed=False)  # type: ignore[arg-type]


# -- JobManager with fake cmds ------------------------------------------------------


def test_job_manager_runs_and_discovers_run_dir(runs_dir: Path,
                                                fake_script: Path) -> None:
    mgr = JobManager(runs_dir=runs_dir)
    job = mgr.launch(["scan", TARGET, "--budget", "200"], name="scan x",
                     cmd=[sys.executable, str(fake_script), str(runs_dir)],
                     discover_run_dir=True)
    assert job.status in {"starting", "running"}
    assert wait_until(lambda: job.status == "done")
    assert job.exit_code == 0
    assert wait_until(lambda: bool(job.run_dir))
    assert (runs_dir / job.run_dir / "config.json").is_file()
    assert "fake scan started" in list(job.log) and "fake scan done" in list(job.log)


def test_job_manager_marks_failure() -> None:
    mgr = JobManager()
    job = mgr.launch(["boom"], cmd=[sys.executable, "-c", "import sys; sys.exit(3)"])
    assert wait_until(lambda: job.status == "failed")
    assert job.exit_code == 3


def test_job_manager_stop_kills_sleeper(sleeper_script: Path) -> None:
    mgr = JobManager()
    job = mgr.launch(["sleep"], cmd=[sys.executable, str(sleeper_script)])
    assert wait_until(lambda: job.status == "running")
    start = time.monotonic()
    assert mgr.stop(job.id) is job
    assert time.monotonic() - start < 10
    assert wait_until(lambda: job.status == "stopped")
    assert mgr.stop("nope") is None


def test_job_manager_all_newest_first_and_public_dict(runs_dir: Path,
                                                      sleeper_script: Path) -> None:
    from vulnem.web.jobs import to_public_dict

    mgr = JobManager(runs_dir=runs_dir)
    first = mgr.launch(["a"], name="a", cmd=[sys.executable, str(sleeper_script)])
    second = mgr.launch(["b"], name="b", cmd=[sys.executable, str(sleeper_script)])
    assert mgr.all()[0].id == second.id and mgr.all()[1].id == first.id
    assert mgr.get(first.id) is first
    data = to_public_dict(second)
    assert set(data) == {"id", "name", "argv", "status", "exit_code", "started_at",
                         "run_dir", "log"}
    assert data["argv"] == ["b"] and isinstance(data["log"], list)
    assert not hasattr(data, "proc")
    mgr.stop(first.id)
    mgr.stop(second.id)


# -- HTTP routes ----------------------------------------------------------------------


def test_get_scan_form(client: TestClient) -> None:
    resp = client.get("/scan")
    assert resp.status_code == 200
    assert 'name="target"' in resp.text
    assert 'placeholder="http://juice-shop:3000"' in resp.text
    for preset in scans.PRESETS:
        assert f'value="{preset}"' in resp.text
    assert "New scan" in resp.text  # nav link


def test_post_scan_bad_target_rerenders_no_job(client: TestClient,
                                               manager: JobManager) -> None:
    resp = client.post("/scan", data={"target": "not a url"})
    assert resp.status_code == 200
    assert "Invalid target" in resp.text
    assert manager.all() == []


def test_post_scan_isolated_launches_job(client: TestClient,
                                         manager: JobManager) -> None:
    resp = client.post("/scan", data={"target": TARGET, "network": "labnet",
                                      "budget": "150", "solo": "on"},
                       follow_redirects=False)
    assert resp.status_code == 303
    job_id = resp.headers["location"].rsplit("/", 1)[-1]
    argv = job_argv(client, job_id)
    assert argv[0] == "scan" and TARGET in argv
    assert "--network" in argv and argv[argv.index("--network") + 1] == "labnet"
    assert "--yes" in argv and "--solo" in argv
    assert argv[argv.index("--budget") + 1] == "150"
    # job page renders
    assert client.get(f"/jobs/{job_id}").status_code == 200
    assert wait_until(lambda: manager.get(job_id).status == "done")


def test_post_scan_gated_shows_authorize(client: TestClient,
                                         manager: JobManager) -> None:
    resp = client.post("/scan", data={"target": TARGET})
    assert resp.status_code == 200
    assert "Authorization required" in resp.text
    assert "reachable from outside an isolated lab network" in resp.text
    assert "illegal in most jurisdictions" in resp.text
    assert "juice-shop" in resp.text
    assert manager.all() == []


def test_authorize_wrong_host_no_job(client: TestClient, manager: JobManager) -> None:
    resp = client.post("/scan", data={"target": TARGET})
    assert resp.status_code == 200
    resp = client.post("/scan/authorize", data={"target": TARGET,
                                                "confirm_host": "wrong-host"})
    assert resp.status_code == 200
    assert "does not match" in resp.text
    assert manager.all() == []


def test_authorize_correct_host_launches(client: TestClient,
                                         manager: JobManager) -> None:
    resp = client.post("/scan/authorize", data={"target": TARGET,
                                                "preset": "thorough",
                                                "confirm_host": "  JUICE-SHOP "},
                       follow_redirects=False)
    assert resp.status_code == 303
    job_id = resp.headers["location"].rsplit("/", 1)[-1]
    argv = job_argv(client, job_id)
    assert "--yes" in argv
    assert argv[argv.index("--budget") + 1] == str(scans.PRESETS["thorough"])


def test_authorize_rejects_stale_bad_data(client: TestClient,
                                          manager: JobManager) -> None:
    # hidden fields are re-validated: a tampered target must not launch
    resp = client.post("/scan/authorize", data={"target": "not a url",
                                                "confirm_host": "juice-shop"})
    assert resp.status_code == 200
    assert "Invalid target" in resp.text
    assert manager.all() == []


def test_job_status_404(client: TestClient) -> None:
    assert client.get("/jobs/bogus/status.json").status_code == 404
    assert client.get("/jobs/bogus").status_code == 404
    assert client.post("/jobs/bogus/stop", follow_redirects=False).status_code == 404


def test_creds_upload_saved_and_passed_never_echoed(
        client: TestClient, runs_dir: Path, manager: JobManager) -> None:
    secret = "SUP3R-SECRET-PASSWORD-9f1e"
    payload = json.dumps({"login_url": "http://juice-shop:3000/#/login",
                          "username": "admin", "password": secret})
    resp = client.post("/scan", data={"target": TARGET, "network": "labnet"},
                       files={"creds": ("c.json", payload.encode(), "application/json")},
                       follow_redirects=False)
    assert resp.status_code == 303
    job_id = resp.headers["location"].rsplit("/", 1)[-1]
    uploads = list((runs_dir / ".uploads").glob("*-creds.json"))
    assert len(uploads) == 1
    argv = job_argv(client, job_id)
    assert "--creds" in argv and argv[argv.index("--creds") + 1] == str(uploads[0])
    for page in (client.get(f"/jobs/{job_id}").text,
                 client.get(f"/jobs/{job_id}/status.json").text,
                 client.get("/scan").text):
        assert secret not in page
    # ...and the runs list skips the .uploads dir entirely
    listing = client.get("/").text
    assert ".uploads" not in listing


def test_uploads_dir_hidden_from_runs_list(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    (runs / ".uploads").mkdir(parents=True)
    (runs / ".uploads" / "abc-creds.json").write_text("{}", encoding="utf-8")
    (runs / FIXTURE_RUN.name).mkdir()
    shutil.copytree(FIXTURE_RUN, runs / FIXTURE_RUN.name, dirs_exist_ok=True)
    settings = Settings(runs_dir=runs, skills_dir=runs)
    resp = TestClient(create_app(settings)).get("/")
    assert resp.status_code == 200
    assert ".uploads" not in resp.text
    assert FIXTURE_RUN.name in resp.text


def test_stop_route(client: TestClient, runs_dir: Path, tmp_path: Path) -> None:
    sleeper = tmp_path / "s.py"
    sleeper.write_text(FAKE_SLEEPER, encoding="utf-8")
    mgr = JobManager(runs_dir=runs_dir,
                     cmd_factory=lambda argv: [sys.executable, str(sleeper)])
    settings = Settings(runs_dir=runs_dir, skills_dir=runs_dir)
    stop_client = TestClient(create_app(settings, jobs_manager=mgr))
    job = mgr.launch(["scan", TARGET], name=f"scan {TARGET}")
    resp = stop_client.post(f"/jobs/{job.id}/stop", follow_redirects=False)
    assert resp.status_code == 303 and resp.headers["location"] == f"/jobs/{job.id}"
    assert wait_until(lambda: mgr.get(job.id).status == "stopped")
    argv = stop_client.get(f"/jobs/{job.id}/status.json").json()["argv"]
    assert argv[0] == "scan"  # display argv survives the stop round-trip


# -- GET /browse (folder picker for the white-box source directory) -------------


def test_browse_lists_subdirs_sorted_and_filters_noise(
        client: TestClient, tmp_path: Path) -> None:
    root = tmp_path / "pickroot"
    root.mkdir()
    for name in ("app", "zeta", ".hidden", "$Recycle.Bin"):
        (root / name).mkdir()
    (root / "a_file.txt").write_text("x", encoding="utf-8")
    resp = client.get("/browse", params={"path": str(root)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["path"] == str(root.resolve())
    assert data["dirs"] == ["app", "zeta"]  # sorted; dot/$ dirs and files gone
    assert data["parent"]  # a tmp dir always has one


def test_browse_defaults_to_home(client: TestClient) -> None:
    from pathlib import Path as P
    resp = client.get("/browse")
    assert resp.status_code == 200
    assert resp.json()["path"] == str(P.home().resolve())


def test_browse_rejects_files_and_missing_paths(
        client: TestClient, tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    assert client.get("/browse", params={"path": str(missing)}).status_code == 400
    a_file = tmp_path / "f.txt"
    a_file.write_text("x", encoding="utf-8")
    assert client.get("/browse", params={"path": str(a_file)}).status_code == 400


def test_browse_drive_root_has_empty_parent(client: TestClient) -> None:
    import tempfile

    root = Path(tempfile.gettempdir()).anchor
    resp = client.get("/browse", params={"path": root})
    assert resp.status_code == 200
    assert resp.json()["parent"] == ""  # can't go above a drive root


def test_scan_page_has_folder_picker(client: TestClient) -> None:
    resp = client.get("/scan")
    assert resp.status_code == 200
    assert 'id="browse-dirs-btn"' in resp.text
    assert 'id="dir-browser"' in resp.text and "<dialog" in resp.text
    assert "/static/dirbrowse.js" in resp.text
