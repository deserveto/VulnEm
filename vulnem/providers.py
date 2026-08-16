"""Provider catalog — the "template" behind any-model support.

litellm routes every provider through a ``provider/model`` string, so any
string already *works*; what this module adds is knowledge: which env var
litellm reads the key from, a few current example models, and whether a
provider needs a key at all. Key-var names below were verified against the
installed litellm (1.96.x) provider sources — several deviate from naive
guesses (``PERPLEXITYAI_API_KEY``, ``TOGETHERAI_API_KEY``, ...).

Unlisted providers are NOT rejected: ``key_var_for`` falls back to the
``<PREFIX>_API_KEY`` naming convention most providers follow, so an exotic
provider just needs its conventional env var set in ``.env``. Pure data +
pure functions; no heavy imports, safe from ``cli``, ``web``, and tests.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Provider:
    """One catalog entry. ``key_var`` None means the provider needs no key."""

    prefix: str
    label: str
    key_var: str | None
    examples: tuple[str, ...] = ()
    note: str = ""


PROVIDERS: dict[str, Provider] = {
    p.prefix: p
    for p in (
        Provider("openai", "OpenAI", "OPENAI_API_KEY",
                 ("openai/gpt-5", "openai/gpt-5-mini", "openai/o4-mini"),
                 "Gateways, ollama, vLLM: keep openai/ and set a Base URL."),
        Provider("anthropic", "Anthropic", "ANTHROPIC_API_KEY",
                 ("anthropic/claude-sonnet-4-5", "anthropic/claude-opus-4-5",
                  "anthropic/claude-haiku-4-5")),
        Provider("openrouter", "OpenRouter", "OPENROUTER_API_KEY",
                 ("openrouter/anthropic/claude-sonnet-4.5",
                  "openrouter/openai/gpt-5",
                  "openrouter/deepseek/deepseek-v3.2"),
                 "Aggregates many providers behind one key."),
        Provider("groq", "Groq", "GROQ_API_KEY",
                 ("groq/llama-3.3-70b-versatile", "groq/qwen/qwen3.6-27b")),
        Provider("gemini", "Google AI Studio", "GEMINI_API_KEY",
                 ("gemini/gemini-2.5-pro", "gemini/gemini-2.5-flash"),
                 "GOOGLE_API_KEY is read as a fallback."),
        Provider("mistral", "Mistral", "MISTRAL_API_KEY",
                 ("mistral/mistral-large-latest", "mistral/devstral-latest",
                  "mistral/devstral-medium-latest")),
        Provider("deepseek", "DeepSeek", "DEEPSEEK_API_KEY",
                 ("deepseek/deepseek-chat", "deepseek/deepseek-v3.2",
                  "deepseek/deepseek-reasoner")),
        Provider("xai", "xAI (Grok)", "XAI_API_KEY",
                 ("xai/grok-4", "xai/grok-code-fast-1")),
        Provider("zai", "Z.ai (GLM)", "ZAI_API_KEY",
                 ("zai/glm-5.1", "zai/glm-5", "zai/glm-5-code"),
                 "Coding-plan keys need ZAI_API_BASE=https://api.z.ai/api/"
                 "coding/paas/v4 in .env; any current model name routes."),
        Provider("perplexity", "Perplexity", "PERPLEXITYAI_API_KEY",
                 ("perplexity/sonar-pro", "perplexity/sonar",
                  "perplexity/sonar-reasoning")),
        Provider("together_ai", "Together AI", "TOGETHERAI_API_KEY",
                 ("together_ai/deepseek-ai/DeepSeek-V3",
                  "together_ai/meta-llama/Llama-4-Maverick-17B-128E-Instruct")),
        Provider("fireworks_ai", "Fireworks AI", "FIREWORKS_AI_API_KEY",
                 ("fireworks_ai/accounts/fireworks/models/kimi-k2-instruct-0905",
                  "fireworks_ai/accounts/fireworks/models/deepseek-v3")),
        Provider("cohere", "Cohere", "COHERE_API_KEY",
                 ("cohere/command-a-03-2025", "cohere/command-r-plus")),
        Provider("cerebras", "Cerebras", "CEREBRAS_API_KEY",
                 ("cerebras/qwen-3-235b-a22b-instruct",
                  "cerebras/llama-3.3-70b")),
        Provider("deepinfra", "DeepInfra", "DEEPINFRA_API_KEY",
                 ("deepinfra/meta-llama/Llama-3.3-70B-Instruct",
                  "deepinfra/Qwen/Qwen2.5-72B-Instruct")),
        Provider("azure", "Azure OpenAI", "AZURE_API_KEY",
                 ("azure/<your-deployment-name>",),
                 "Also set AZURE_API_BASE and AZURE_API_VERSION; the model "
                 "string is your deployment name."),
        Provider("bedrock", "AWS Bedrock", None,
                 ("bedrock/us.anthropic.claude-3-7-sonnet-20250219-v1:0",),
                 "Uses AWS credentials (AWS_ACCESS_KEY_ID / SECRET_ACCESS_KEY "
                 "/ AWS_REGION), not a single API key."),
        Provider("vertex_ai", "Google Vertex AI", None,
                 ("vertex_ai/gemini-2.5-pro",),
                 "Uses GOOGLE_APPLICATION_CREDENTIALS, not an API key."),
        Provider("ollama_chat", "Ollama (local)", None,
                 ("ollama_chat/qwen3:8b", "ollama_chat/llama3.3:70b"),
                 "Local server, no key. Set the Base URL unless it is "
                 "http://localhost:11434."),
        Provider("ollama", "Ollama (raw completion)", None,
                 ("ollama/qwen3:8b",),
                 "Prefer ollama_chat/ for agents; OLLAMA_API_KEY is optional."),
    )
}


def prefix_of(model: str) -> str:
    """The provider prefix of a litellm model string ("" when malformed)."""
    if "/" not in model:
        return ""
    return model.split("/", 1)[0].strip().lower()


def lookup(model: str) -> Provider | None:
    """The catalog entry for a model string, or None when unlisted."""
    return PROVIDERS.get(prefix_of(model))


def is_keyless(model: str) -> bool:
    """True only for catalog providers that need no API key."""
    provider = lookup(model)
    return provider is not None and provider.key_var is None


def convention_key_var(prefix: str) -> str:
    """The env var most litellm providers read for an unlisted prefix."""
    return prefix.strip().upper().replace("-", "_") + "_API_KEY"


def key_var_for(model: str) -> str | None:
    """The env var holding this model's key — catalog first, then convention.

    Returns None only for catalog keyless providers (no key to set); any
    unlisted provider gets its conventional ``<PREFIX>_API_KEY`` var.
    """
    provider = lookup(model)
    if provider is not None:
        return provider.key_var
    prefix = prefix_of(model)
    if not prefix:
        return None
    return convention_key_var(prefix)


def known_key_vars() -> set[str]:
    """Every catalog key var — the scrub list for error sanitization."""
    return {p.key_var for p in PROVIDERS.values() if p.key_var}


def picker_rows() -> list[dict]:
    """Catalog rows for the setup-page provider picker (no secrets)."""
    return [
        {
            "prefix": p.prefix,
            "label": p.label,
            "key_var": p.key_var or "",
            "examples": list(p.examples),
            "note": p.note,
        }
        for p in sorted(PROVIDERS.values(), key=lambda p: p.label.lower())
    ]
