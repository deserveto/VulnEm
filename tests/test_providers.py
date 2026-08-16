"""Tests for vulnem/providers.py — the any-provider catalog + convention.

The catalog is the single source of provider knowledge (key vars, keyless
locals, examples); these tests pin its integrity and the
``<PREFIX>_API_KEY`` convention fallback that replaces the old
unknown-provider rejections. Plus the VULNEM_API_BASE -> litellm ``api_base``
pass-through at the agent-runtime call site.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

from vulnem import providers

# -- catalog integrity ----------------------------------------------------------


def test_catalog_entries_wellformed() -> None:
    assert len(providers.PROVIDERS) >= 15
    for provider in providers.PROVIDERS.values():
        assert provider.prefix and provider.label
        assert provider.prefix == provider.prefix.strip().lower()
        assert provider.examples, provider.prefix  # every entry shows some
        for example in provider.examples:
            assert example.startswith(provider.prefix + "/"), example
        if provider.key_var is not None:
            assert re.fullmatch(r"[A-Z0-9_]+", provider.key_var)


def test_key_vars_match_litellm_conventions() -> None:
    # the non-obvious names, verified against litellm 1.96.x provider sources
    assert providers.PROVIDERS["perplexity"].key_var == "PERPLEXITYAI_API_KEY"
    assert providers.PROVIDERS["together_ai"].key_var == "TOGETHERAI_API_KEY"
    assert providers.PROVIDERS["fireworks_ai"].key_var == "FIREWORKS_AI_API_KEY"
    assert providers.PROVIDERS["gemini"].key_var == "GEMINI_API_KEY"
    assert providers.PROVIDERS["openai"].key_var == "OPENAI_API_KEY"
    assert providers.PROVIDERS["anthropic"].key_var == "ANTHROPIC_API_KEY"
    assert providers.PROVIDERS["openrouter"].key_var == "OPENROUTER_API_KEY"
    assert providers.PROVIDERS["groq"].key_var == "GROQ_API_KEY"


def test_keyless_providers_are_the_local_ones() -> None:
    assert providers.is_keyless("ollama_chat/qwen3:8b")
    assert providers.is_keyless("ollama/llama3")
    assert not providers.is_keyless("openai/gpt-5")
    assert not providers.is_keyless("unknown-thing/x")  # convention != keyless


# -- resolution + convention fallback --------------------------------------------


def test_key_var_for_catalogued() -> None:
    assert providers.key_var_for("anthropic/claude-x") == "ANTHROPIC_API_KEY"
    assert providers.key_var_for("Groq/Mixed-Case") == "GROQ_API_KEY"  # lowered


def test_key_var_for_unlisted_uses_convention() -> None:
    assert providers.key_var_for("zorp/tiny") == "ZORP_API_KEY"
    assert providers.key_var_for("some-host/model") == "SOME_HOST_API_KEY"


def test_key_var_for_keyless_and_malformed() -> None:
    assert providers.key_var_for("ollama_chat/x") is None
    assert providers.key_var_for("no-slash") is None
    assert providers.key_var_for("") is None


def test_lookup_and_prefix() -> None:
    assert providers.lookup("mistral/large").prefix == "mistral"
    assert providers.lookup("nope/x") is None
    assert providers.prefix_of("xai/grok-4") == "xai"
    assert providers.prefix_of("bare") == ""


def test_known_key_vars_cover_catalog() -> None:
    key_vars = providers.known_key_vars()
    assert "OPENAI_API_KEY" in key_vars and "TOGETHERAI_API_KEY" in key_vars
    assert all(var.endswith("_API_KEY") for var in key_vars)


def test_picker_rows_sorted_and_complete() -> None:
    rows = providers.picker_rows()
    labels = [row["label"] for row in rows]
    assert labels == sorted(labels, key=str.lower)
    assert len(rows) == len(providers.PROVIDERS)
    assert set(rows[0]) == {"prefix", "label", "key_var", "examples", "note"}


# -- VULNEM_API_BASE flows to the litellm call -----------------------------------


class _BareSession:
    """Just the attributes _completion_sync touches — no loop, no sandbox."""


def _bare_session(**settings_kwargs) -> _BareSession:
    from vulnem.config import Settings

    session = _BareSession()
    session.completion_fn = None
    session.settings = Settings(**settings_kwargs)
    session.messages = [{"role": "user", "content": "hi"}]
    session.tool_schemas = lambda: []
    session.record = SimpleNamespace(name="unit")
    return session


def test_completion_sync_passes_api_base(monkeypatch) -> None:
    import litellm

    from vulnem.agents.session import AgentSession

    captured: dict = {}
    monkeypatch.setattr(litellm, "completion",
                        lambda **kwargs: captured.update(kwargs))
    AgentSession._completion_sync(
        _bare_session(model="openai/gpt-5", api_base="http://gw:9/v1"))
    assert captured["model"] == "openai/gpt-5"
    assert captured["api_base"] == "http://gw:9/v1"


def test_completion_sync_omits_api_base_when_unset(monkeypatch) -> None:
    import litellm

    from vulnem.agents.session import AgentSession

    captured: dict = {}
    monkeypatch.setattr(litellm, "completion",
                        lambda **kwargs: captured.update(kwargs))
    AgentSession._completion_sync(_bare_session(model="groq/x"))
    assert "api_base" not in captured
