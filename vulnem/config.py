"""Runtime configuration for VulnEm.

Settings come from environment variables (VULNEM_*) and an optional .env file
in the project root. Provider API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...)
are read directly by litellm from the environment; VULNEM_API_BASE optionally
points every provider call at an OpenAI-compatible endpoint (ollama, vLLM,
LiteLLM proxy, gateways) and is passed to litellm per-call as ``api_base``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_LLM = "openai/gpt-5"
SANDBOX_IMAGE = "vulnem-sandbox:latest"
SANDBOX_USER = "pentester"
DEFAULT_MAX_TURNS = 60
DEFAULT_CHILD_MAX_TURNS = 30
DEFAULT_MAX_AGENTS = 8
DEFAULT_CMD_TIMEOUT = 120
DEFAULT_MAX_TOTAL_TOKENS = 4_000_000
DEFAULT_MAX_CONCURRENT_EXEC = 4
OUTPUT_TRUNCATE_CHARS = 12_000


@dataclass(slots=True)
class Settings:
    """Everything a scan needs, resolved once at startup."""

    model: str = DEFAULT_LLM
    api_base: str | None = None
    max_turns: int = DEFAULT_MAX_TURNS
    child_max_turns: int = DEFAULT_CHILD_MAX_TURNS
    max_agents: int = DEFAULT_MAX_AGENTS
    cmd_timeout: int = DEFAULT_CMD_TIMEOUT
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS
    max_concurrent_exec: int = DEFAULT_MAX_CONCURRENT_EXEC
    sandbox_image: str = SANDBOX_IMAGE
    sandbox_user: str = SANDBOX_USER
    docker_network: str | None = None
    skills_dir: Path = field(default_factory=lambda: Path("skills"))
    runs_dir: Path = field(default_factory=lambda: Path("runs"))
    yes: bool = False

    @classmethod
    def load(cls, *, project_root: Path | None = None) -> Settings:
        """Build settings from the environment, loading .env if present."""
        root = project_root or Path.cwd()
        _load_dotenv(root / ".env")
        return cls(
            model=os.environ.get("VULNEM_LLM", DEFAULT_LLM),
            api_base=os.environ.get("VULNEM_API_BASE") or None,
            max_turns=int(os.environ.get("VULNEM_MAX_TURNS", DEFAULT_MAX_TURNS)),
            child_max_turns=int(
                os.environ.get("VULNEM_CHILD_MAX_TURNS", DEFAULT_CHILD_MAX_TURNS)
            ),
            max_agents=int(os.environ.get("VULNEM_MAX_AGENTS", DEFAULT_MAX_AGENTS)),
            cmd_timeout=int(os.environ.get("VULNEM_CMD_TIMEOUT", DEFAULT_CMD_TIMEOUT)),
            max_total_tokens=int(
                os.environ.get("VULNEM_MAX_TOTAL_TOKENS", DEFAULT_MAX_TOTAL_TOKENS)
            ),
            max_concurrent_exec=int(
                os.environ.get("VULNEM_MAX_CONCURRENT_EXEC", DEFAULT_MAX_CONCURRENT_EXEC)
            ),
            sandbox_image=os.environ.get("VULNEM_SANDBOX_IMAGE", SANDBOX_IMAGE),
            docker_network=os.environ.get("VULNEM_DOCKER_NETWORK") or None,
            skills_dir=Path(os.environ.get("VULNEM_SKILLS_DIR", "skills")),
            runs_dir=Path(os.environ.get("VULNEM_RUNS_DIR", "runs")),
            yes=os.environ.get("VULNEM_YES", "").strip() in {"1", "true", "yes"},
        )


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, # comments, no interpolation.

    Values are only set if the variable is not already in the environment so
    real env vars always win over the file.
    """
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value
