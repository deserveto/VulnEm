# VulnEm

Autonomous AI penetration-testing agent for **authorized** security testing.
A coordinator LLM agent decomposes the assessment and spawns specialist
agents that work in parallel inside an isolated Docker sandbox full of
security tooling, driven through recon → testing → validated PoC → report,
Strix-style. A local web UI (`vulnem ui`) mirrors the whole flow in the
browser — onboarding, launching scans, and watching them live.

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
`findings.json` (structured), `findings.sarif` (CI/code-scanning),
`report.pdf` (export), `transcript.jsonl` (every turn, tool call, and
result — the data source for the live UI). Watch any run with
`vulnem tui runs/<id>`; re-export SARIF/PDF with `vulnem report runs/<id>`;
consolidate several runs of one target with `vulnem report --merge
runs/<id1> runs/<id2> ...` (one run is a sample — re-finds merge with
per-run attribution).

## Web UI

```bash
vulnem ui   # opens the local app at http://127.0.0.1:8756
```

The web app starts with a **Setup wizard** (`/setup`): it runs the
`vulnem doctor` environment checks in the browser (Docker daemon, sandbox
image, proxy sidecar, LLM model, API key, skill packs) with one-click
fixes — edit the model + API key straight into `.env`, build the sandbox
image as a watchable job, and run a safe demo (throwaway isolated Juice
Shop lab + full scan) once the blockers are green. From there the **New
scan** form offers the CLI's presets behind the same typed-host
authorization confirmation, runs stream live (agent tree, tool calls,
findings over SSE), and reports are browsable in-page. The CLI remains the
power path with identical semantics — the web app drives the same `vulnem`
commands as subprocesses and reads the same `runs/` output.

The interface follows the repo's **StudioBlank design system** (`DESIGN.md`):
light, strictly flat, zero border-radius, monochrome Inter + IBM Plex Mono
with semantic color reserved for status. A sun/moon toggle (Heroicons) in
the top bar switches to a faithfully inverted dark theme, persisted per
browser.

## Scanning your own lab target

```bash
# Reusable lab you can also browse at http://localhost:3000 (Juice Shop),
# http://localhost:4280 (DVWA) and http://localhost:5001 (VulnApp):
docker compose -p vulnem-lab -f lab/docker-compose.yml up -d
vulnem scan http://juice-shop:3000 --network vulnem-lab_labnet

# Authenticated scan: credentials live in a file, never in a prompt:
vulnem scan http://juice-shop:3000 --network vulnem-lab_labnet \
  --creds lab/juice-shop-creds.json --budget 200
vulnem scan http://dvwa --network vulnem-lab_labnet \
  --creds lab/dvwa-creds.json --budget 200

# White-box: mount the target's source (read-only) — semgrep + agent code
# reading; findings carry file:line and a fix patch:
vulnem scan http://vuln-app:5000 --network vulnem-lab_labnet \
  --source lab/vulnapp --budget 100

# CI / PR gate: headless, exit 1 on findings (or --fail-on <severity>),
# PR-sized scans focused on the diff:
vulnem scan http://vuln-app:5000 --network vulnem-lab_labnet \
  --ci --fail-on high --scope-mode diff --source . --yes

# Any containerized target: attach the sandbox to the same Docker network.
```

Scanning a target outside an isolated network requires interactive
authorization confirmation (or `--yes` with `VULNEM_YES=1` for CI).

## How it works

```
┌───────────────────────┐  create_agent / wait / message / stop
│  ROOT (orchestrator)  │──────────────────────────────┐
│  never touches target │◀─────────────────────────────┘
└──────────┬────────────┘   completion reports, alerts
           │ spawns in parallel
   ┌───────┼─────────────┬──────────────┐
   ▼       ▼             ▼              ▼
┌────────┐ ┌────────┐ ┌────────┐  ┌──────────┐   tool calls
│spec-1  │ │spec-2  │ │spec-3  │  │ ...      │ ─────────────▶ ┌──────────────────────┐
│hands-on│ │hands-on│ │hands-on│  │          │ ◀───────────── │  Sandbox container   │
└────────┘ └────────┘ └────────┘  └──────────┘  tool results  │  Debian + nmap,      │
                                                          │  sqlmap, nuclei,     │
┌────────────────────────────┐                             │  ffuf, katana, ...   │
│ runs/<id>/ findings.json   │◀────────────────────────────┘        ┌──────────────┐
│   report.md  transcript    │   HTTP (Docker network, internal     │  lab target  │
│   state.json  sessions/    │       for labs)                      │ (Juice Shop) │
└────────────────────────────┘                                      └──────────────┘
```

- **Coordinator** (`vulnem/agents/coordinator.py`) — single owner of the
  agent graph: statuses (`running|waiting|completed|stopped|crashed|failed`),
  parent/child tree, per-agent mailboxes (a message to a parked agent
  revives it), scan-wide turn/token budget, JSON snapshot for resume.
- **Root agent** — delegation-only orchestrator; it has *no* execution
  tools and its prompt forbids touching the target. It decomposes the
  assessment (`skills/coordination/root_agent.md` is its playbook), spawns
  specialists, parks in `wait_for_agents` (one wait — no polling), and
  synthesizes the final report from their completion reports.
- **Specialists** (`vulnem/agents/session.py`) — Phase 1 hands-on toolset
  (`exec_command`, `read_skill`, `report_finding`, `think`) plus the Phase 3
  browser tools (`browser_navigate/click/fill/read_page/evaluate/screenshot`,
  a stateful headless-Chromium session per agent) and proxy tools
  (`list_requests`, `view_request`, `repeat_request`, `view_sitemap` over the
  captured traffic), plus `agent_finish`, which files a structured completion
  report into the parent's session. Each agent is an asyncio task on the
  shared sandbox; a crashed child is isolated and reported, the scan continues.
- **Lifecycle tools are the only exit** — an agent ends only via
  `finish_scan` (root/solo) or `agent_finish` (specialist); plain text
  never ends a turn.
- **Browser + proxy** (`vulnem/tools/`, `vulnem/proxy/`) — every scan runs a
  mitmproxy sidecar next to the sandbox. The sandbox's HTTP traffic is
  routed through it; the sidecar's addon enforces the scope allowlist
  (out-of-scope requests get a 403 and are logged to the transcript + run
  dir), records every exchange to a flow log the proxy tools read back, and
  `repeat_request` replays through the same enforcement. Browser
  screenshots land in `runs/<id>/artifacts/<agent>/` and are cited as
  finding evidence.
- **Authenticated scans** (`vulnem/auth.py`, `--creds <file>`) — the host
  logs in (browser form / API / raw cookies) before any agent runs and seeds
  the session into every browser context plus a curl cookie jar
  (`-b /home/pentester/cookies.txt`, `-H @/home/pentester/.vulnem/auth-header.txt`
  for token auth). Credential values never enter a prompt or the transcript.
- **Skills** (`skills/*.md`) — 15 markdown methodology packs loaded on
  demand: recon, sql_injection, xss, browser_testing, command_injection,
  broken_access_control, idor, ssrf, auth_jwt, ssti, file_upload,
  open_redirect, prototype_pollution, business_logic,
  coordination/root_agent. Add a new `.md` file (subdirs allowed) with a
  `description:` frontmatter and the agents can use it.
- **Scope** (`vulnem/scope.py`) — every agent inherits the same
  system-verified scope block; network isolation for labs is the real guard.
- **Findings** (`vulnem/report/findings.py`) — pydantic-validated; every
  finding carries evidence + PoC + remediation + CVSS + reporter;
  overlapping findings from different agents (same endpoint + class) merge
  into one with combined evidence and attribution.
- **Reports** (`vulnem/report/`) — every scan writes `report.md`,
  `findings.json`, `findings.sarif` (SARIF 2.1.0 — validated against the
  OASIS schema, severity→level mapping, CWE rule ids, stable fingerprints
  for CI dedupe) and `report.pdf` (severity table + per-finding detail with
  monospace PoC/evidence). `vulnem report <run_dir>` re-exports both, and
  `vulnem report --merge <run_dir>... [--out DIR]` consolidates several runs
  of the same target into one report — same endpoint+class re-finds collapse
  (highest severity/confidence/CVSS wins, evidence stacked per reporter,
  never blended) and each finding lists every run that reported it.
- **White-box mode** (`--source <dir>`) — the target's source is mounted
  read-only into the sandbox; the image carries semgrep plus a vendored
  ruleset (works on internet-less lab networks). Static hits are treated as
  leads; agents validate them dynamically and file findings with `file` +
  `line` and a `fix_patch` unified diff written from the real code.
- **Live/replay UI** (`vulnem tui <run_dir>`) — Textual TUI over
  `transcript.jsonl`: agent graph with status colors, live tool/event
  stream, findings table, traffic/scope-block/screenshot stats. Replay a
  recorded run at `--speed` (default auto), or `--follow` a live scan.
- **CI mode** (`--ci`) — headless, one `VULNEM_RESULT` summary line,
  exit 1 when findings at/above `--fail-on` severity exist;
  `--scope-mode diff` (+ `--diff-file` or a `--source` git repo) focuses
  the scan on files/endpoints from the PR diff — prompt-level narrowing,
  the three scope layers are never weakened. This repo's own CI
  (`.github/workflows/ci.yml`) runs VulnEm keylessly against its lab and
  verifies the fail-on-findings contract.
- **Evals** (`scripts/eval.py`) — recall / false-positive-rate / cost
  benchmarks against ground truth (`evals/ground_truth/*.json`) for
  Juice Shop, DVWA and VulnApp; scores recorded runs or launches fresh
  scans, and writes tables to `evals/results/`.

## Configuration

| Env var | Default | Meaning |
| --- | --- | --- |
| `VULNEM_LLM` | `openai/gpt-5` | litellm model string (`anthropic/claude-...`, `openrouter/...`, ...) |
| `OPENAI_API_KEY` etc. | — | provider keys, read by litellm |
| `VULNEM_MAX_TURNS` | `60` | per-agent turn cap (root/solo) |
| `VULNEM_CHILD_MAX_TURNS` | `30` | default turn cap for specialists |
| `VULNEM_MAX_AGENTS` | `8` | agent cap for the graph |
| `VULNEM_MAX_TOTAL_TOKENS` | `4000000` | scan-wide hard token budget |
| `VULNEM_CMD_TIMEOUT` | `120` | per-command sandbox timeout (s) |
| `VULNEM_MAX_CONCURRENT_EXEC` | `4` | concurrent sandbox commands across agents |
| `VULNEM_DOCKER_NETWORK` | — | attach sandbox to this network |
| `VULNEM_YES` | — | `1` skips the authorization prompt |

Useful flags: `vulnem scan --budget N` (scan-wide turn budget),
`--max-agents N`, `--solo` (Phase 1 single-agent mode),
`--creds <file>` (authenticated scan — secrets stay out of prompts),
`--source <dir>` (white-box: source mounted read-only), `--ci` +
`--fail-on <severity>` (headless gate), `--scope-mode diff` +
`--diff-file <f>` (PR-sized scans), `--no-proxy` (drop the mitmproxy
sidecar layer), `vulnem resume <run_dir> [--extend-turns N]` (continue an
interrupted scan from its snapshot), `vulnem tui <run_dir> [--follow]`
(live/replay UI), `vulnem report <run_dir>` (re-export SARIF + PDF),
`vulnem report --merge <runs>...` (cross-run consolidation).

## Safety model

1. **Isolation** — everything executes inside a disposable container as a
   non-root user. Lab runs attach it to an *internal* Docker network: the
   sandbox has no internet route, so out-of-scope targets are unreachable by
   construction.
2. **Proxy allowlist** — the sandbox's HTTP traffic flows through a
   scope-enforcing mitmproxy sidecar: out-of-scope requests are blocked
   (403 / CONNECT denied) and logged. Browser navigations are host-checked
   against the same scope before reaching Chromium.
3. **Prompt scope** — every agent inherits the same system-verified scope
   block; three layers, none of them optional.
4. **Authorization gate** — non-lab scans require interactive confirmation.
5. **Non-destructive rules** — enforced via system prompt (no DoS, no data
   destruction, minimal reversible payloads; validation over damage).
6. **Budgets** — per-agent turn caps plus a scan-wide turn/token budget;
   agents get wrap-up grace, then force-stop.

## Roadmap

- [x] Phase 1 — single agent, sandbox, skills, findings, demo lab
- [x] Phase 2 — coordinator + specialist agents: parallel graph, mailboxes,
  budgets, crash isolation, cross-agent dedupe, snapshot/resume
- [x] Phase 3 — browser tool (Playwright) + HTTP proxy with scope enforcement,
  authenticated scans, DVWA second lab target
- [x] Phase 4 — live TUI, SARIF/PDF reports, white-box mode (semgrep +
  file:line + fix patches), CI mode with PR-check workflow, eval harness
  (recall/FP/cost), VulnApp planted-flaw lab target
- [x] Phase 5 — interface-first web UI: setup wizard, scan driver, live run
  viewing, report browsing (`vulnem ui`), StudioBlank design system with
  dark mode

## Legal

Provided for authorized security testing and education only (Apache-2.0).
Unauthorized testing is illegal in most jurisdictions.
