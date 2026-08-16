"""Environment checks for the web setup wizard — ``vulnem doctor``, browser-shaped.

Mirrors :func:`vulnem.cli.cmd_doctor` exactly (same checks, same verdicts) but
returns structured :class:`Check` objects the /setup template can render. The
Docker client is injectable so tests run without a daemon; provider keys are
checked for PRESENCE only — a variable's value never enters a Check. The one
deliberate exception is :func:`llm_ping`: an on-demand 1-token round-trip the
user explicitly asks for, whose result is scrubbed of key values before it
leaves this module.
"""

from __future__ import annotations

import os
import time
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


# -- on-demand provider round-trip -------------------------------------------------

_PING_TIMEOUT_S = 20.0
_ERROR_MAX_CHARS = 300


def llm_ping(model: str, *, api_key: str | None = None,
             timeout: float = _PING_TIMEOUT_S,
             completion_fn: Any | None = None) -> dict:
    """One minimal provider round-trip for the setup page's Test button.

    Sends a 1-token ``ping`` completion with retries off, using the exact
    model + key a scan would use. ``completion_fn`` is the test seam
    (None -> ``litellm.completion``), mirroring AgentSession's injection
    idiom. Returns ``{"ok", "model", "latency_ms", "error"}`` where ``model``
    is the served model the provider reports; error text is classified,
    scrubbed of key values, and truncated — a key never leaves this function.
    """
    import litellm

    fn = completion_fn or litellm.completion
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,  # litellm renames it for gpt-5/o-series models
        "timeout": timeout,
        "num_retries": 0,
    }
    if api_key:
        kwargs["api_key"] = api_key
    start = time.perf_counter()
    try:
        response = fn(**kwargs)
    except Exception as exc:  # classified below; never re-raised to the route
        error = _scrub_secrets(_classify_error(exc), api_key)
        return {"ok": False, "model": model,
                "latency_ms": _elapsed_ms(start), "error": error[:_ERROR_MAX_CHARS]}
    served = str(getattr(response, "model", "") or "")
    return {"ok": True, "model": served or model,
            "latency_ms": _elapsed_ms(start), "error": ""}


def _elapsed_ms(start: float) -> int:
    return round((time.perf_counter() - start) * 1000)


def _classify_error(exc: Exception) -> str:
    """Turn a litellm exception into a hint the user can act on."""
    from litellm import exceptions as litellm_exceptions

    if isinstance(exc, litellm_exceptions.AuthenticationError):
        return f"authentication failed (401) — the API key was rejected: {exc}"
    if isinstance(exc, litellm_exceptions.PermissionDeniedError):
        return f"permission denied (403) — the key lacks access to this model: {exc}"
    if isinstance(exc, litellm_exceptions.NotFoundError):
        return f"not found (404) — check the model name: {exc}"
    if isinstance(exc, litellm_exceptions.RateLimitError):
        return f"rate limited (429) — the key works but is throttled: {exc}"
    if isinstance(exc, litellm_exceptions.ServiceUnavailableError):
        return f"provider unavailable (5xx) — transient, try again: {exc}"
    if isinstance(exc, litellm_exceptions.Timeout):
        return f"timed out — the provider did not answer within the limit: {exc}"
    if isinstance(exc, litellm_exceptions.APIConnectionError):
        return f"could not reach the provider — network or base URL problem: {exc}"
    return f"{type(exc).__name__}: {exc}"


def _scrub_secrets(text: str, submitted_key: str | None = None) -> str:
    """Replace every provider key value (plus the submitted one) with ``***``.

    litellm errors don't normally embed keys, but a custom base URL can echo
    one back — defense in depth for the write-only rule.
    """
    values = {submitted_key,
              *(os.environ.get(var) for var in PROVIDER_KEY_VARS.values())}
    for value in values:
        if value and len(value) >= 8:  # short strings would mangle messages
            text = text.replace(value, "***")
    return text
