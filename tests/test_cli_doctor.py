"""Tests for `vulnem doctor --ping-llm` (keyless: llm_ping is faked).

Follows the test_merge.py CLI pattern: Settings/_resolve_paths are swapped
for fakes so the real repo .env and runs/ are never touched, and
``vulnem.web.checks.llm_ping`` is monkeypatched so no provider call happens.
Docker is forced unreachable so output and exit codes are deterministic on
machines with and without a daemon.
"""

from __future__ import annotations

from types import SimpleNamespace

import docker
import pytest

from vulnem import cli


@pytest.fixture()
def doctor_env(tmp_path, monkeypatch):
    skills = tmp_path / "skills"
    skills.mkdir()
    (skills / "recon.md").write_text(
        "---\ndescription: find the attack surface\n---\n# recon\n",
        encoding="utf-8")
    settings = SimpleNamespace(model="openai/gpt-5",
                               sandbox_image="vulnem-sandbox:missing",
                               skills_dir=skills)
    # cli.main() also calls Settings.load itself before dispatching, so the
    # fake needs a callable .load, not just a constructor.
    monkeypatch.setattr(cli, "Settings",
                        SimpleNamespace(load=lambda **kwargs: settings))
    monkeypatch.setattr(cli, "_resolve_paths", lambda s: s)

    def no_daemon():
        raise docker.errors.DockerException("no daemon")

    monkeypatch.setattr(docker, "from_env", no_daemon)
    return monkeypatch


def test_doctor_ping_llm_success(doctor_env, capsys) -> None:
    doctor_env.setattr("vulnem.web.checks.llm_ping",
                       lambda model, **kw: {"ok": True,
                                            "model": "gpt-5-served",
                                            "latency_ms": 7, "error": ""})
    assert cli.main(["doctor", "--ping-llm"]) == 1  # docker down still fails
    out = capsys.readouterr().out
    assert "pinging openai/gpt-5" in out
    assert "gpt-5-served" in out
    assert "answered" in out


def test_doctor_ping_llm_failure(doctor_env, capsys) -> None:
    doctor_env.setattr("vulnem.web.checks.llm_ping",
                       lambda model, **kw: {"ok": False, "model": model,
                                            "latency_ms": 31,
                                            "error": "keyrejected-401"})
    assert cli.main(["doctor", "--ping-llm"]) == 1
    assert "keyrejected-401" in capsys.readouterr().out


def test_doctor_without_flag_never_pings(doctor_env, capsys) -> None:
    def boom(model, **kw):
        raise AssertionError("llm_ping must not run without --ping-llm")

    doctor_env.setattr("vulnem.web.checks.llm_ping", boom)
    assert cli.main(["doctor"]) == 1
    assert "pinging" not in capsys.readouterr().out


def _point_settings_at(monkeypatch, tmp_path, **overrides) -> None:
    """Swap cli.Settings for a fake with the given fields (doctor_env's
    _resolve_paths + docker.from_env patches stay in force)."""
    skills = tmp_path / "doctor-skills"
    skills.mkdir(exist_ok=True)
    if not (skills / "recon.md").exists():
        (skills / "recon.md").write_text(
            "---\ndescription: find the attack surface\n---\n# recon\n",
            encoding="utf-8")
    fields = {"model": "openai/gpt-5", "sandbox_image": "vulnem-sandbox:missing",
              "skills_dir": skills, "api_base": None}
    fields.update(overrides)
    settings = SimpleNamespace(**fields)
    monkeypatch.setattr(cli, "Settings",
                        SimpleNamespace(load=lambda **kwargs: settings))


def test_doctor_unlisted_provider_names_convention_var(
        doctor_env, tmp_path, monkeypatch, capsys) -> None:
    _point_settings_at(monkeypatch, tmp_path, model="zorp/tiny-xl")
    monkeypatch.setenv("ZORP_API_KEY", "set-in-env")
    assert cli.main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "ZORP_API_KEY is set" in out
    assert "manually" not in out  # the old unknown-provider dead end is gone


def test_doctor_keyless_provider_needs_no_key(
        doctor_env, tmp_path, monkeypatch, capsys) -> None:
    _point_settings_at(monkeypatch, tmp_path, model="ollama_chat/qwen3:8b")
    assert cli.main(["doctor"]) == 1
    assert "needs no API key" in capsys.readouterr().out


def test_doctor_shows_api_base_when_set(
        doctor_env, tmp_path, monkeypatch, capsys) -> None:
    _point_settings_at(monkeypatch, tmp_path, api_base="http://gw:9/v1")
    assert cli.main(["doctor"]) == 1
    assert "VULNEM_API_BASE is set" in capsys.readouterr().out
