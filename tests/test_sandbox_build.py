"""Tests for vulnem/sandbox/docker.py build_image (no Docker daemon needed).

Pins the regression where a cold-cache build died mid-step: docker-py's
default 60s read timeout cancels the streamed build during the first silent
minute of a long RUN (go install nuclei compiles quietly for many minutes).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import docker
import pytest

from vulnem.sandbox.docker import build_image


class FakeBuildAPI:
    def __init__(self, chunks: list[dict]) -> None:
        self.chunks = chunks
        self.build_kwargs: dict | None = None

    def build(self, **kwargs):
        self.build_kwargs = kwargs
        return iter(self.chunks)


def test_build_image_constructs_client_without_timeout(monkeypatch, capsys) -> None:
    """The build client must have NO read timeout — silent compile steps
    inside one RUN would otherwise cancel the build after docker-py's
    60-second default."""
    api = FakeBuildAPI([
        {"stream": "Step 1/20 : FROM golang:bookworm\n"},
        {"stream": " ---> abc123\n"},
    ])
    captured: dict = {}

    def fake_from_env(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(api=api)

    monkeypatch.setattr(docker, "from_env", fake_from_env)

    build_image(dockerfile_dir=Path("containers"), tag="vulnem-sandbox:test")

    assert captured == {"timeout": None}  # the regression pin
    assert api.build_kwargs is not None
    assert api.build_kwargs["tag"] == "vulnem-sandbox:test"
    assert api.build_kwargs["rm"] is True
    out = capsys.readouterr().out
    assert "Step 1/20" in out and "image vulnem-sandbox:test ready" in out


def test_build_image_raises_sandbox_error_on_error_chunk(monkeypatch) -> None:
    api = FakeBuildAPI([{"stream": "...\n"}, {"error": "go: module download failed"}])

    def fake_from_env(**kwargs):
        return SimpleNamespace(api=api)

    monkeypatch.setattr("vulnem.sandbox.docker.docker",
                        SimpleNamespace(from_env=fake_from_env))

    with pytest.raises(Exception, match="image build failed"):
        build_image(dockerfile_dir=Path("containers"), tag="vulnem-sandbox:test")


def test_sandbox_client_default_is_60s() -> None:
    """Documents why build_image must override: docker-py's stock default."""
    assert docker.constants.DEFAULT_TIMEOUT_SECONDS == 60
