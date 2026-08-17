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
  (exec/browser/proxy tools), `report/` (findings, merge, sarif, pdf,
  mdrender), `ui/` (TUI + pure reducer `state.py`), `web/` (local web app),
  `providers.py` (provider catalog: key vars, keyless locals, examples),
  `scope.py`, `scan.py`, `cli.py`
- `skills/*.md` — vulnerability methodology packs (markdown, not code)
- `lab/` — docker-compose targets: juice-shop :3000, dvwa :4280, vulnapp
  :5001 (host ports); `evals/` — ground truth + results
- `runs/<id>/` — scan output (gitignored): transcript.jsonl, findings.json,
  report.md/pdf, sarif, state.json; `runs/<ts>-<host>-merged-<id>/` —
  cross-run consolidated reports (`vulnem report --merge`, no transcript;
  web shows them with a "merged" chip)
- `tests/fixtures/run/` — committed fixture run (regenerate via
  `scripts/make_test_fixture.py`); real `runs/` is dev-machine only

## Environment & commands (Windows + Git Bash)

Venv at `.venv` — always `.venv/Scripts/python` / `.venv/Scripts/vulnem`.

```bash
.venv/Scripts/python -m pytest tests/ -q        # 234 tests, no Docker/LLM needed
.venv/Scripts/python -m ruff check vulnem/ tests/ scripts/
.venv/Scripts/python scripts/mock_e2e.py        # keyless full-stack, ~45s
.venv/Scripts/python scripts/mock_resume.py     # keyless interrupt+resume e2e
                                                # (needs the vulnem-lab lab up)
python scripts/bootstrap.py                      # fresh checkout: venv+install+
                                                # doctor+web wizard (--no-ui to skip)
docker compose -p vulnem-lab -f lab/docker-compose.yml up -d
```

- `mock_e2e.py` wrapper exits 0 when every check passes (2 = regression);
  it internally asserts the scripted demo scan itself exits 1 (findings
  found, the CI fail-on-findings contract).
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
  web `.env` editor is write-only; `/setup/test-llm` and `doctor --ping-llm`
  spend the key on their one probe call and scrub it from every error).
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
- Provider knowledge lives ONLY in `vulnem/providers.py` (key vars verified
  against litellm sources; several deviate from naive guesses). Never
  re-hardcode a provider→key-var map elsewhere; unlisted prefixes use the
  `<PREFIX>_API_KEY` convention via `providers.key_var_for`. `VULNEM_API_BASE`
  (OpenAI-compatible endpoints) flows env → `Settings.api_base` → per-call
  litellm `api_base`.
- Background bash with `| tail` can zombie on Windows/Git Bash — prefer
  checking `docker images`/port state over trusting task status. Kill
  servers by PID from `netstat`, never by image name.
- Root's `create_agent max_turns` overrides `VULNEM_CHILD_MAX_TURNS`; for
  slow Pro models use budget 300+ and child caps 55+.
- Sandbox shims: `httpx/subfinder/katana/nuclei` and `semgrep` in the image
  are shell wrappers (real binaries are `*.real` beside them) appending
  `-disable-update-check` (PD tools; katana adds `-scp <baked chromium> -nos`
  only when `-hl/-hh` is present — katana rejects those flags otherwise),
  and `--metrics=off --disable-version-check` (semgrep) — tool phone-home
  hits the scope proxy and pollutes blocked-event logs. Extend the wrappers
  in `containers/Dockerfile`, never bypass them; the one exception is the
  nuclei template bake, which must call `nuclei.real -update-templates`
  because `-duc` silently no-ops template updates. The vendored semgrep
  rules (`containers/semgrep-rules/`) must keep a rule language for every
  stack you scan — semgrep silently scans ZERO files when no rule matches
  the target's languages (check `.paths.scanned` in the JSON, not just
  results). `scripts/tool_probe.py` runs the wrapped tools through a real
  sandbox+proxy stack (no LLM) to verify all of this end-to-end.
- `vulnem report` rewrites report.md too; agent summaries are rendered by
  `vulnem/report/mdrender.py` (not raw pasted markdown).
