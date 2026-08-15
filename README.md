# VulnEm

Autonomous AI penetration-testing agent for **authorized** security testing.
One LLM agent + an isolated Docker sandbox full of security tooling, driven
through recon → testing → validated PoC → report, Strix-style.

> [!WARNING]
> VulnEm actively probes its target. Only run it against systems you own or
> have explicit written permission to test. The `demo` command builds an
> isolated lab (internal Docker network, no internet) so you can develop and
> evaluate safely.

## Quickstart

```bash
# 1. Install (Python 3.11+, Docker required)
cd VulnEm
python -m venv .venv && .venv/Scripts/activate   # Windows (use bin/activate on unix)
pip install -e ".[dev]"

# 2. Configure the LLM (litellm format) — copy .env.example to .env
#    VULNEM_LLM=openai/gpt-5
#    OPENAI_API_KEY=sk-...

# 3. Build the sandbox image (~5-10 min first time)
vulnem build

# 4. Verify the environment
vulnem doctor

# 5. One-command demo: isolated Juice Shop lab + full scan + report
vulnem demo
```

Reports land in `runs/<timestamp>-<host>/` — `report.md` (human),
`findings.json` (structured), `transcript.jsonl` (every turn, tool call, and
result — the data source for a future live UI).

## Scanning your own lab target

```bash
# Reusable lab you can also browse at http://localhost:3000:
docker compose -p vulnem-lab -f lab/docker-compose.yml up -d
vulnem scan http://juice-shop:3000 --network vulnem-lab_labnet

# Any containerized target: attach the sandbox to the same Docker network.
```

Scanning a target outside an isolated network requires interactive
authorization confirmation (or `--yes` with `VULNEM_YES=1` for CI).

## How it works

```
┌────────────┐   tool calls    ┌──────────────────────┐
│  LLM agent │ ──────────────▶ │  Sandbox container   │
│ (litellm)  │ ◀────────────── │  Debian + nmap,      │
└────────────┘   tool results  │  sqlmap, nuclei,     │
      │                         │  ffuf, katana, ...   │
      │ findings                └──────────┬───────────┘
      ▼                                     │ HTTP (Docker network,
┌────────────────────────────┐              │  internal for labs)
│ runs/<id>/ findings.json   │◀─────────────┘
│            report.md       │        ┌──────────────┐
│            transcript.jsonl│        │  lab target  │
└────────────────────────────┘        │ (Juice Shop) │
                                      └──────────────┘
```

- **Agent loop** (`vulnem/agent/loop.py`) — hand-rolled on litellm, no
  framework. The scan only ends via the `finish_scan` tool; text-only turns
  get nudged, then stopped (the most important lifecycle lesson from Strix).
- **Tools** (`vulnem/agent/tools.py`) — `exec_command` (sandboxed shell),
  `read_skill`, `report_finding`, `think`, `finish_scan`.
- **Skills** (`skills/*.md`) — markdown methodology packs loaded on demand:
  recon, sql_injection, xss, broken_access_control, command_injection. Add a
  new `.md` file with a `description:` frontmatter and the agent can use it.
- **Scope** (`vulnem/scope.py`) — prompt-level authoritative scope block, plus
  network isolation for labs (the real guard).
- **Findings** (`vulnem/report/findings.py`) — pydantic-validated; every
  finding must carry evidence + PoC + remediation; deduped, severity-ordered,
  rendered to markdown + JSON.

## Configuration

| Env var | Default | Meaning |
| --- | --- | --- |
| `VULNEM_LLM` | `openai/gpt-5` | litellm model string (`anthropic/claude-...`, `openrouter/...`, ...) |
| `OPENAI_API_KEY` etc. | — | provider keys, read by litellm |
| `VULNEM_MAX_TURNS` | `60` | agent turn cap |
| `VULNEM_MAX_TOTAL_TOKENS` | `4000000` | hard token budget |
| `VULNEM_CMD_TIMEOUT` | `120` | per-command sandbox timeout (s) |
| `VULNEM_DOCKER_NETWORK` | — | attach sandbox to this network |
| `VULNEM_YES` | — | `1` skips the authorization prompt |

## Safety model (Phase 1)

1. **Isolation** — everything executes inside a disposable container as a
   non-root user. Lab runs attach it to an *internal* Docker network: the
   sandbox has no internet route, so out-of-scope targets are unreachable by
   construction.
2. **Authorization gate** — non-lab scans require interactive confirmation.
3. **Non-destructive rules** — enforced via system prompt (no DoS, no data
   destruction, minimal reversible payloads; validation over damage).

## Roadmap

- [x] Phase 1 — single agent, sandbox, skills, findings, demo lab
- [ ] Phase 2 — coordinator + specialist subagents (recon/exploit/validate),
  agent graph with mailboxes (Strix-style)
- [ ] Phase 3 — browser tool (Playwright) + HTTP proxy with scope enforcement
- [ ] Phase 4 — live TUI/web viewer over `transcript.jsonl`, snapshot/resume,
  SARIF output, white-box mode

## Legal

Provided for authorized security testing and education only (Apache-2.0).
Unauthorized testing is illegal in most jurisdictions.
