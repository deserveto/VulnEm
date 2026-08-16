"""Environment checks for the web setup wizard — ``vulnem doctor``, browser-shaped.

Mirrors :func:`vulnem.cli.cmd_doctor` exactly (same checks, same verdicts) but
returns structured :class:`Check` objects the /setup template can render. The
Docker client is injectable so tests run without a daemon; provider keys are
checked for PRESENCE only — a variable's value never enters a Check.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnem.config import Settings

#: litellm provider prefix -> the env var litellm reads the key from
#: (same map as ``cmd_doctor``).
PROVIDER_KEY_VARS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "groq": "GROQ_API_KEY",
}

#: checks whose failure blocks scanning (the / banner + the safe-demo gate).
CRITICAL_KEYS = frozenset({"docker", "sandbox_image", "provider_key", "skills"})


@dataclass(slots=True)
class Check:
    """One environment check result. ``detail`` must never contain secrets."""

    key: str
    label: str
    state: str  # "ok" | "warn" | "fail"
    detail: str
    fix: str = ""  # "" | "build" | "set_key"


def environment_checks(settings: Settings,
                       docker_client: Any | None = None) -> list[Check]:
    """Run the doctor checks and return them in display order.

    ``docker_client`` is the test seam (None -> lazy ``docker.from_env()``).
    Docker being unreachable collapses to a single failed docker check and
    skips the image checks, exactly like the CLI doctor.
    """
    checks = [_model_check(settings)]
    client = docker_client
    if client is None:
        try:
            import docker

            client = docker.from_env()
        except Exception as exc:  # ImportError or no daemon
            checks.append(Check("docker", "Docker daemon", "fail",
                                f"Docker not reachable: {exc}"))
            client = None
    if client is not None:
        try:
            client.ping()
        except Exception as exc:
            checks.append(Check("docker", "Docker daemon", "fail",
                                f"Docker not reachable: {exc}"))
        else:
            checks.append(Check("docker", "Docker daemon", "ok",
                                "daemon reachable"))
            checks.extend(_image_checks(client, settings))
    checks.append(_provider_key_check(settings))
    checks.append(_skills_check(settings))
    return checks


def critical_failures(checks: list[Check]) -> list[Check]:
    """The subset of failed checks that blocks scanning."""
    return [c for c in checks if c.key in CRITICAL_KEYS and c.state == "fail"]


# -- individual checks -----------------------------------------------------------


def _model_check(settings: Settings) -> Check:
    if settings.model:
        return Check("model", "LLM model", "ok", settings.model)
    return Check("model", "LLM model", "warn", "no model configured")


def _image_checks(client: Any, settings: Settings) -> list[Check]:
    from docker.errors import ImageNotFound

    from vulnem.proxy.manager import SIDECAR_IMAGE

    out: list[Check] = []
    try:
        client.images.get(settings.sandbox_image)
        out.append(Check("sandbox_image", "Sandbox image", "ok",
                         f"{settings.sandbox_image} present"))
    except ImageNotFound:
        out.append(Check("sandbox_image", "Sandbox image", "fail",
                         f"{settings.sandbox_image} missing — run `vulnem build`",
                         fix="build"))
    except Exception as exc:  # daemon died between ping and get
        out.append(Check("sandbox_image", "Sandbox image", "fail",
                         f"could not query Docker: {exc}"))
    try:
        client.images.get(SIDECAR_IMAGE)
        out.append(Check("sidecar_image", "Proxy sidecar image", "ok",
                         f"{SIDECAR_IMAGE} present"))
    except ImageNotFound:
        out.append(Check("sidecar_image", "Proxy sidecar image", "warn",
                         f"{SIDECAR_IMAGE} missing — pulled on first use "
                         "(needs internet once)"))
    except Exception as exc:  # missing sidecar is never scan-blocking
        out.append(Check("sidecar_image", "Proxy sidecar image", "warn",
                         f"could not query Docker: {exc}"))
    return out


def _provider_key_check(settings: Settings) -> Check:
    provider = settings.model.split("/", 1)[0]
    key_var = PROVIDER_KEY_VARS.get(provider)
    if key_var is None:
        return Check("provider_key", "Provider API key", "warn",
                     "custom provider — verify its key yourself")
    if os.environ.get(key_var):
        return Check("provider_key", "Provider API key", "ok",
                     f"{key_var} is set")
    return Check("provider_key", "Provider API key", "fail",
                 f"{key_var} is NOT set", fix="set_key")


def _skills_check(settings: Settings) -> Check:
    from vulnem.agent.tools import _list_skills

    packs = _list_skills(Path(settings.skills_dir))
    if not packs:
        return Check("skills", "Skill packs", "fail",
                     f"no packs found in {settings.skills_dir}")
    return Check("skills", "Skill packs", "ok",
                 f"{len(packs)} packs in {settings.skills_dir}")
