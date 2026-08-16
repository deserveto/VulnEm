# AGENTS.md — VulnEm workspace instructions

Authorized-security-testing AI pentest agent (Strix-style): coordinator LLM
delegates to specialist agents inside a Docker sandbox, driven through
recon → testing → validated PoC → report. Repo is **PRIVATE** on GitHub
(deserveto/VulnEm) — never flip visibility without explicit user consent.

Read before touching sensitive areas: `PLAN.md` (living roadmap + phase
history), `README.md` ("How it works" + "Safety model"), `DESIGN.md` (web UI
design system), `skills/` (agent methodology packs).

## Layout

- `vulnem/` — the tool. `agent/` (loop+prompt), `agents/` (coordinator,
  sessions), `sandbox/` (Docker), `proxy/` (mitmproxy sidecar), `tools/`
  (exec/browser/proxy tools), `report/` (findings, sarif, pdf, mdrender),
  `ui/` (TUI + pure reducer `state.py`), `web/` (local web app), `scope.py`,
  `scan.py`, `cli.py`
- `skills/*.md` — vulnerability methodology packs (markdown, not code)
- `lab/` — docker-compose targets: juice-shop :3000, dvwa :4280, vulnapp
  :5001 (host ports); `evals/` — ground truth + results
- `runs/<id>/` — scan output (gitignored): transcript.jsonl, findings.json,
  report.md/pdf, sarif, state.json
- `tests/fixtures/run/` — committed fixture run (regenerate via
  `scripts/make_test_fixture.py`); real `runs/` is dev-machine only

## Environment & commands (Windows + Git Bash)

Venv at `.venv` — always `.venv/Scripts/python` / `.venv/Scripts/vulnem`.

```bash
.venv/Scripts/python -m pytest tests/ -q        # 170 tests, no Docker/LLM needed
.venv/Scripts/python -m ruff check vulnem/ tests/ scripts/
.venv/Scripts/python scripts/mock_e2e.py        # keyless full-stack, ~21s
docker compose -p vulnem-lab -f lab/docker-compose.yml up -d
```

- `mock_e2e.py` MUST exit 1 (findings found). rc 0 or 2 = regression.
- Tests must pass on a fresh checkout: runs/-dependent tests are skipif-gated
  in `tests/conftest.py`; web tests use the fixture run or tmp_path only.
- `.env` holds real provider keys — never commit, print, or echo its values.
- CI (`.github/workflows/ci.yml`): lint-test + pr-check (keyless lab scan
  asserting fail-on-findings + SARIF/PDF artifacts).

## Hard rules (architecture boundaries)

- **Scope = prompt + network + proxy — three layers, never weaken one.**
  Web/CLI `--yes` only after an explicit authorization gate (typed host) or
  on an isolated Docker network.
- **Lifecycle tools are the only exit**: `finish_scan`/`agent_finish`.
  `wait_for_agents` blocks once — no polling loops.
- **`transcript.jsonl` is the product**: complete + stable; every UI (TUI,
  web) derives from it. `vulnem/ui/state.py` reducer is pure — unknown event
  types degrade to a one-liner, never dropped.
- **Skills are markdown, not code** — new vuln knowledge lands in `skills/`.
- **Root agent never touches the target**; it only delegates.
- **Secrets never enter prompts or transcripts** (creds via `--creds` file;
  web `.env` editor is write-only).
- Budgets bound every real run (turns + tokens).
- Don't weaken the negative-results-are-not-findings block in
  `vulnem/agent/prompt.py`.

## Web UI (`vulnem/web/`, `vulnem ui`)

- Drives the CLI via `python -m vulnem.cli ...` subprocesses (`jobs.py`) —
  no new scan semantics; views read `runs/` + the reducer.
- Styling follows `DESIGN.md` (StudioBlank): light, strictly flat, 0px
  radius, no shadows, monochrome Inter/IBM Plex Mono with semantic color
  only as status. Dark mode = CSS token inversion via `[data-theme="dark"]`.
  No CDNs, no npm/build steps — assets in `vulnem/web/static/`.
- Tails transcripts in **binary mode with byte offsets** (Windows newline
  translation corrupts text-mode tails — see `web/tail.py`, `ui/tui.py`).

## Conventions & gotchas

- Ruff: line-length 100, rules E,W,F,I,UP,B,SIM,RUF. Lazy imports for heavy
  deps (fastapi/docker/uvicorn imported inside functions, matching `cli.py`).
- Background bash with `| tail` can zombie on Windows/Git Bash — prefer
  checking `docker images`/port state over trusting task status. Kill
  servers by PID from `netstat`, never by image name.
- Root's `create_agent max_turns` overrides `VULNEM_CHILD_MAX_TURNS`; for
  slow Pro models use budget 300+ and child caps 55+.
- `vulnem report` rewrites report.md too; agent summaries are rendered by
  `vulnem/report/mdrender.py` (not raw pasted markdown).
