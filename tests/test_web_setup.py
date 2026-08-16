"""Tests for the W3 setup wizard (vulnem/web/checks.py + envfile.py + routes).

No Docker daemon, no LLM, no real .env: docker is faked with stub clients
(injected via ``app.state.docker_client``), the JobManager runs a trivial
fake command instead of the CLI, and the wizard's .env target is re-pointed
to a tmp path via ``app.state.env_path`` before any POST touches the disk.
API-key values are asserted to be write-only everywhere.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import docker
import pytest

from vulnem.config import Settings
from vulnem.proxy.manager import SIDECAR_IMAGE
from vulnem.web import checks, envfile
from vulnem.web.app import create_app, get_checks
from vulnem.web.jobs import JobManager

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

SANDBOX = "vulnem-sandbox:latest"
KEY_VARS = ("VULNEM_LLM", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
            "OPENROUTER_API_KEY", "GROQ_API_KEY")
FAKE_CMD = [sys.executable, "-c", "print('wizard fake job')"]
SLEEPER_CMD = [sys.executable, "-c",
               "import time; print('sleeping', flush=True); time.sleep(30)"]


def wait_until(predicate, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class FakeImages:
    def __init__(self, missing: set[str]) -> None:
        self.missing = missing

    def get(self, ref: str):
        if ref in self.missing:
            raise docker.errors.ImageNotFound(f"image not found: {ref}")
        return object()


class FakeDockerClient:
    """Just enough docker client: ping + images.get, fully scripted."""

    def __init__(self, missing: tuple[str, ...] = (),
                 ping_error: Exception | None = None) -> None:
        self.images = FakeImages(set(missing))
        self.ping_error = ping_error
        self.pings = 0

    def ping(self):
        self.pings += 1
        if self.ping_error is not None:
            raise self.ping_error
        return True


@pytest.fixture()
def skills_dir(tmp_path: Path) -> Path:
    skills = tmp_path / "skills"
    skills.mkdir()
    (skills / "recon.md").write_text(
        "---\ndescription: find the attack surface\n---\n# recon\n",
        encoding="utf-8")
    return skills


@pytest.fixture()
def isolated_keys(monkeypatch):
    """Drop every var the wizard touches (and restore the originals after,
    even when the route itself calls os.environ.update mid-test)."""
    for var in KEY_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture()
def wizard(tmp_path: Path, skills_dir: Path, isolated_keys) -> SimpleNamespace:
    runs = tmp_path / "runs"
    runs.mkdir()
    manager = JobManager(runs_dir=runs, cmd_factory=lambda argv: list(FAKE_CMD))
    settings = Settings(runs_dir=runs, skills_dir=skills_dir)
    app = create_app(settings, jobs_manager=manager)
    app.state.env_path = tmp_path / ".env"
    app.state.docker_client = FakeDockerClient()
    return SimpleNamespace(app=app, client=TestClient(app), manager=manager,
                           settings=settings, env_path=app.state.env_path)


def by_key(checklist: list[checks.Check]) -> dict[str, checks.Check]:
    return {c.key: c for c in checklist}


# -- checks.environment_checks -----------------------------------------------------


def test_checks_all_ok(skills_dir: Path, isolated_keys, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-value-never-shown")
    settings = Settings(model="openai/gpt-5", skills_dir=skills_dir)
    checklist = checks.environment_checks(settings, FakeDockerClient())
    assert [c.state for c in checklist] == ["ok"] * len(checklist)
    assert checks.critical_failures(checklist) == []
    key = by_key(checklist)["provider_key"]
    assert key.detail == "OPENAI_API_KEY is set"  # name only, never the value
    assert by_key(checklist)["model"].detail == "openai/gpt-5"
    assert "1 pack" in by_key(checklist)["skills"].detail


def test_checks_docker_unreachable(skills_dir: Path, isolated_keys,
                                    monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    settings = Settings(skills_dir=skills_dir)
    checklist = checks.environment_checks(
        settings, FakeDockerClient(ping_error=ConnectionError("no pipe")))
    docker_check = by_key(checklist)["docker"]
    assert docker_check.state == "fail" and "no pipe" in docker_check.detail
    assert docker_check in checks.critical_failures(checklist)
    # mirrors cmd_doctor: image checks are skipped when the daemon is down
    assert "sandbox_image" not in by_key(checklist)
    assert "sidecar_image" not in by_key(checklist)


def test_checks_docker_from_env_failure(skills_dir: Path, isolated_keys,
                                        monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x")

    def boom():
        raise docker.errors.DockerException("no daemon at all")

    monkeypatch.setattr(docker, "from_env", boom)
    settings = Settings(skills_dir=skills_dir)
    checklist = checks.environment_checks(settings)  # docker_client=None path
    assert by_key(checklist)["docker"].state == "fail"


def test_checks_sandbox_image_missing(skills_dir: Path, isolated_keys,
                                       monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    settings = Settings(skills_dir=skills_dir)
    checklist = checks.environment_checks(
        settings, FakeDockerClient(missing=(SANDBOX,)))
    sandbox = by_key(checklist)["sandbox_image"]
    assert sandbox.state == "fail" and sandbox.fix == "build"
    assert sandbox in checks.critical_failures(checklist)
    assert by_key(checklist)["sidecar_image"].state == "ok"


def test_checks_sidecar_missing_is_only_a_warn(skills_dir: Path,
                                               isolated_keys,
                                               monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    settings = Settings(skills_dir=skills_dir)
    checklist = checks.environment_checks(
        settings, FakeDockerClient(missing=(SIDECAR_IMAGE,)))
    sidecar = by_key(checklist)["sidecar_image"]
    assert sidecar.state == "warn" and sidecar not in checks.critical_failures(
        checklist)
    assert by_key(checklist)["sandbox_image"].state == "ok"


def test_checks_unknown_provider_warns(skills_dir: Path, isolated_keys) -> None:
    settings = Settings(model="myprovider/model-x", skills_dir=skills_dir)
    checklist = checks.environment_checks(settings, FakeDockerClient())
    key = by_key(checklist)["provider_key"]
    assert key.state == "warn" and "verify its key" in key.detail
    assert key not in checks.critical_failures(checklist)


def test_checks_provider_key_missing(skills_dir: Path, isolated_keys) -> None:
    settings = Settings(model="openai/gpt-5", skills_dir=skills_dir)
    checklist = checks.environment_checks(settings, FakeDockerClient())
    key = by_key(checklist)["provider_key"]
    assert key.state == "fail" and key.fix == "set_key"
    assert key in checks.critical_failures(checklist)


def test_checks_skills_zero_packs_fails(isolated_keys, tmp_path: Path,
                                        monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    settings = Settings(skills_dir=tmp_path / "nope")
    checklist = checks.environment_checks(settings, FakeDockerClient())
    skill_check = by_key(checklist)["skills"]
    assert skill_check.state == "fail"
    assert skill_check in checks.critical_failures(checklist)


# -- envfile ------------------------------------------------------------------------


def test_read_env_parses_like_config(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "# comment line\n"
        "\n"
        "VULNEM_LLM=openai/gpt-5\n"
        "  SPACED = value  \n"
        "QUOTED=\"double quoted\"\n"
        "SINGLE='single quoted'\n"
        "noequalsline\n"
        "DUP=first\n"
        "DUP=second\n",
        encoding="utf-8")
    values = envfile.read_env(path)
    assert values == {
        "VULNEM_LLM": "openai/gpt-5",
        "SPACED": "value",
        "QUOTED": "double quoted",
        "SINGLE": "single quoted",
        "DUP": "second",  # later duplicates win, like os.environ
    }
    assert envfile.read_env(tmp_path / "absent.env") == {}


def test_upsert_creates_new_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    envfile.upsert_env(path, {"VULNEM_LLM": "openai/gpt-5"})
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#")  # small header for a brand-new file
    assert "VULNEM_LLM=openai/gpt-5" in text
    assert not list(tmp_path.glob("*.tmp"))  # atomic replace left no temp


def test_upsert_updates_in_place_preserving_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text(
        "# top comment\n"
        "OTHER=keep-me\n"
        "VULNEM_LLM=openai/gpt-4\n"
        "\n"
        "# bottom comment\n",
        encoding="utf-8")
    envfile.upsert_env(path, {"VULNEM_LLM": "anthropic/claude-5",
                              "ANTHROPIC_API_KEY": "sk-ant-test"})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == [
        "# top comment",
        "OTHER=keep-me",
        "VULNEM_LLM=anthropic/claude-5",  # same position, new value
        "",
        "# bottom comment",
        "ANTHROPIC_API_KEY=sk-ant-test",  # missing keys append at the end
    ]
    assert not list(tmp_path.glob("*.tmp"))


def test_upsert_removes_later_duplicates(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("A=1\nB=2\nA=stale\n", encoding="utf-8")
    envfile.upsert_env(path, {"A": "9"})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == ["A=9", "B=2"]


# -- get_checks cache ----------------------------------------------------------------


def test_get_checks_cached_within_ttl(wizard: SimpleNamespace) -> None:
    fake = wizard.app.state.docker_client
    first = get_checks(wizard.app, wizard.settings)
    second = get_checks(wizard.app, wizard.settings)
    assert fake.pings == 1  # second hit served from the 30s cache
    assert first is second
    get_checks(wizard.app, wizard.settings, force=True)
    assert fake.pings == 2


# -- HTTP routes ----------------------------------------------------------------------


def test_get_setup_page(wizard: SimpleNamespace) -> None:
    resp = wizard.client.get("/setup")
    assert resp.status_code == 200
    for label in ("Docker daemon", "Sandbox image", "Proxy sidecar image",
                  "LLM model", "Provider API key", "Skill packs"):
        assert label in resp.text, label
    assert "Environment checks" in resp.text
    assert "Re-run checks" in resp.text
    assert "already built" in resp.text  # fake client: image present
    assert "disabled" in resp.text  # demo gated while provider key missing
    assert 'href="/setup"' in resp.text  # nav link
    assert wizard.client.get("/setup?refresh=1").status_code == 200


def test_post_env_saves_and_never_echoes_key(wizard: SimpleNamespace) -> None:
    resp = wizard.client.post("/setup/env",
                              data={"model": "openai/gpt-5",
                                    "api_key": "sk-test-123"},
                              follow_redirects=False)
    assert resp.status_code == 303 and resp.headers["location"].startswith(
        "/setup?")
    text = wizard.env_path.read_text(encoding="utf-8")
    assert "VULNEM_LLM=openai/gpt-5" in text
    assert "OPENAI_API_KEY=sk-test-123" in text
    assert os.environ["VULNEM_LLM"] == "openai/gpt-5"
    assert os.environ["OPENAI_API_KEY"] == "sk-test-123"
    assert wizard.settings.model == "openai/gpt-5"
    for page in (wizard.client.get(resp.headers["location"]).text,
                 wizard.client.get("/setup").text):
        assert "sk-test-123" not in page  # write-only: never rendered back


def test_post_env_blank_key_without_any_existing(wizard: SimpleNamespace) -> None:
    resp = wizard.client.post("/setup/env",
                              data={"model": "openai/gpt-5", "api_key": ""})
    assert resp.status_code == 200
    assert "API key required" in resp.text
    assert not wizard.env_path.exists()  # nothing written on error
    assert wizard.manager.all() == []


def test_post_env_blank_key_keeps_existing_file_key(wizard: SimpleNamespace) -> None:
    wizard.env_path.write_text("OPENAI_API_KEY=file-key\n",
                               encoding="utf-8")
    resp = wizard.client.post("/setup/env",
                              data={"model": "openai/gpt-5", "api_key": ""},
                              follow_redirects=False)
    assert resp.status_code == 303
    text = wizard.env_path.read_text(encoding="utf-8")
    assert "OPENAI_API_KEY=file-key" in text  # untouched
    assert "VULNEM_LLM=openai/gpt-5" in text  # model still saved


def test_post_env_blank_key_keeps_existing_env_key(wizard: SimpleNamespace,
                                                   monkeypatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "env-key")
    resp = wizard.client.post("/setup/env",
                              data={"model": "groq/llama-x", "api_key": ""},
                              follow_redirects=False)
    assert resp.status_code == 303
    text = wizard.env_path.read_text(encoding="utf-8")
    assert "VULNEM_LLM=groq/llama-x" in text
    assert "GROQ_API_KEY" not in text  # the env var already provides it


def test_post_env_rejects_model_without_provider(wizard: SimpleNamespace) -> None:
    for bad in ("", "gpt-5-no-slash"):
        resp = wizard.client.post("/setup/env", data={"model": bad})
        assert resp.status_code == 200
        assert "provider prefix" in resp.text
    assert not wizard.env_path.exists()


def test_post_env_unknown_provider(wizard: SimpleNamespace) -> None:
    resp = wizard.client.post("/setup/env",
                              data={"model": "weird/model", "api_key": "k"})
    assert resp.status_code == 200
    assert "manually" in resp.text
    assert not wizard.env_path.exists()


def test_post_build_launches_job(wizard: SimpleNamespace) -> None:
    resp = wizard.client.post("/setup/build", follow_redirects=False)
    assert resp.status_code == 303
    job_id = resp.headers["location"].rsplit("/", 1)[-1]
    job = wizard.manager.get(job_id)
    assert job is not None and job.argv == ["build"]
    assert job.name == "build sandbox image"
    assert wait_until(lambda: job.status == "done")
    page = wizard.client.get(f"/jobs/{job_id}")
    assert page.status_code == 200 and "vulnem build" in page.text


def test_post_build_redirects_to_running_build(wizard: SimpleNamespace) -> None:
    first = wizard.manager.launch(["build"], name="build sandbox image",
                                  cmd=SLEEPER_CMD)
    try:
        resp = wizard.client.post("/setup/build", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"] == f"/jobs/{first.id}"  # no double run
        assert len(wizard.manager.all()) == 1
    finally:
        wizard.manager.stop(first.id)


def test_post_demo_blocked_when_not_ready(wizard: SimpleNamespace) -> None:
    wizard.app.state.docker_client = FakeDockerClient(
        ping_error=ConnectionError("down"))
    resp = wizard.client.post("/setup/demo")
    assert resp.status_code == 409
    assert "fix first" in resp.text
    assert wizard.manager.all() == []  # nothing launched


def test_post_demo_launches_when_ready(wizard: SimpleNamespace,
                                       monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    resp = wizard.client.post("/setup/demo", follow_redirects=False)
    assert resp.status_code == 303
    job_id = resp.headers["location"].rsplit("/", 1)[-1]
    job = wizard.manager.get(job_id)
    assert job is not None and job.argv == ["demo"]
    assert job.name == "safe demo scan"
    assert wait_until(lambda: job.status == "done")


def test_runs_banner_when_setup_incomplete(wizard: SimpleNamespace) -> None:
    resp = wizard.client.get("/")  # provider key missing -> critical failure
    assert resp.status_code == 200
    assert "finish setup" in resp.text


def test_runs_no_banner_when_setup_complete(wizard: SimpleNamespace,
                                            monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    resp = wizard.client.get("/")
    assert resp.status_code == 200
    assert "finish setup" not in resp.text
