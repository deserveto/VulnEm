# VulnEm — Build Plan

Autonomous AI penetration-testing agent for **authorized** security testing,
built Strix-style: LLM agents + an isolated Docker sandbox full of security
tooling, driven through recon → testing → validated PoC → report.

This is the living roadmap. Current state: **Phase 5 shipped**.

---

## Reference architecture (what Strix does, what we take)

Researched from `usestrix/strix` (52k⭐, Apache-2.0). Their stack: Python 3.12,
`openai-agents` SDK + LiteLLM, Kali Docker sandbox, ~50 markdown skills,
Go/Bubble Tea TUI + React viewer. We keep the core ideas, skip the product
surface (cloud, TUI-in-Go) until the engine is proven.

Design principles we carry over — these are the load-bearing decisions:

1. **Root delegates, never tests.** The orchestrator's prompt forbids touching
   the target; all hands-on work goes to specialists. Keeps orchestrator
   context small and forces parallelism.
2. **Lifecycle tools are the only exit.** An agent ends only by calling
   `finish` (root) or `agent_finish` (child). Plain text never ends a turn —
   no stalling mid-scan.
3. **Findings require proof.** Every finding ships a validated PoC and
   evidence, not a suspicion. This is the whole value over static scanners.
4. **Scope enforced in two layers.** Prompt-level scope (system-verified
   targets) AND network-level enforcement (sandbox network / proxy allowlist).
   Prompts alone leak.
5. **Skills as markdown, not code.** Knowledge packs iterate 100x faster than
   code; keep them outside the binary.

## Stack

| Piece | Choice | Notes |
|---|---|---|
| Language | Python 3.11+ | done |
| LLM access | LiteLLM (`VULNEM_LLM`, provider-agnostic) | done |
| Agent loop | hand-rolled loop (`vulnem/agent/loop.py`) | revisit only if we need streaming/interruption |
| Sandbox | Docker + Kali tools image (`containers/Dockerfile`) | done |
| Browser | Playwright headless Chromium in sandbox | done (Phase 3) |
| Proxy | mitmproxy (Python-scriptable) | done (Phase 3) |
| UI | Textual TUI or local web viewer over `transcript.jsonl` | Phase 4 |
| Reports | `report.md` + `findings.json` (done) → SARIF, PDF | Phase 4 |
| Test targets | Juice Shop + DVWA (`lab/`) | done |

---

## Phase 1 — Single agent, one target ✅ (shipped 2026-08-15)

One LLM agent + sandbox + scope guardrails + structured findings, proven
against Juice Shop. Commits: `c2ea140`, `a72445a`.

What exists:

- `vulnem scan <target>` — single-agent scan (`--network`, `--model`,
  `--max-turns`, `--yes`)
- `vulnem demo` — one-command isolated lab: Juice Shop + scan + report
- `vulnem build` / `vulnem doctor` / `vulnem skills`
- Agent tools: `exec_command`, `read_skill`, `report_finding`, `think`,
  `finish` (lifecycle-only exit ✓)
- `vulnem/scope.py` — target allowlist enforced before the agent ever runs
- `vulnem/sandbox/docker.py` — container lifecycle, exec, teardown
- `vulnem/report/findings.py` — structured findings + `report.md`
- `runs/<ts>-<host>/` — `report.md`, `findings.json`, `transcript.jsonl`
  (full turn/tool log — the data source for the future live UI)
- 5 skills: `recon`, `sql_injection`, `xss`, `command_injection`,
  `broken_access_control`
- Tests: `test_scope.py`, `test_findings.py`; `scripts/mock_e2e.py`
- 7 real runs recorded; system prompt tuned from the first real transcript

## Phase 2 — Coordinator + specialist agents ✅ (shipped 2026-08-16)

The single agent became an addressable multi-agent graph. Verified by the
self-checking multi-agent mock e2e (real Docker lab, scripted LLM, no API
key): root spawns 3 specialists in parallel, parks in `wait_for_agents`,
dedupes overlapping findings with merged attribution.

What exists now (on top of Phase 1):

- `vulnem/agents/coordinator.py` — single owner of graph state:
  statuses (`running|waiting|completed|stopped|crashed|failed`),
  parent/child tree, per-agent mailboxes (queue + wake event — a message
  to a parked agent revives it), scan-wide turn/token budget with
  `--budget` / `resume --extend-turns`, JSON snapshot/restore.
- `vulnem/agents/session.py` — `AgentSession` + async agent loop; each
  agent is an asyncio task on one sandbox (exec/LLM in worker threads,
  concurrency-capped); child crash isolation; wrap-up grace then
  force-stop on budget exhaustion.
- Root agent — delegation-only orchestrator (no exec tools, prompt
  forbids touching the target): `create_agent`, `view_agent_graph`,
  `send_message_to_agent`, `wait_for_agents` (blocks once — no polling),
  `stop_agent`, `finish_scan`.
- Children — Phase 1 hands-on toolset + `agent_finish`, which files a
  structured completion report (status/summary/findings/recommendations)
  into the parent's session as a high-priority message.
- Findings: CVSS vector/score, per-agent attribution, cross-agent dedupe
  (same endpoint + class → one finding, merged evidence, both reporters).
- Skills: 14 packs (8 new classes + `coordination/root_agent` playbook).
- `runs/<id>/` now also carries `state.json` + `sessions/*.json`;
  `vulnem resume <run_dir>` rebuilds the graph and continues interrupted
  agents (dangling tool calls repaired on restore).
- `transcript.jsonl`: every event attributed (`agent_ctx`), plus
  agent_created / agent_status / agent_message / message_delivered
  lifecycle events — the data source for the Phase 4 live graph UI.
- Phase 1 behavior preserved: `vulnem scan --solo` runs the single-agent
  mode on the same engine.

Pending: ~~a real-LLM `vulnem demo`~~ — done 2026-08-16 (`runs/20260815-181256-...`,
budget 150 turns / 3.1M tokens): root parked in `wait_for_agents` while 5
specialists ran in parallel; 2 failed mid-run (turn caps + a fragile target)
and their alerts flowed to root, which respawned/finished cleanly; final
report: critical SQLi (manual boolean-based confirmation + CVSS 7.5),
medium CORS, low missing-CSP — per-finding quality strictly above Phase 1
(CVSS + attribution + merged-evidence schema), count within Phase 1's
0–11 real-run variance. Cross-agent dedupe exercised by the mock e2e +
tests (this run's specialists covered disjoint classes). Follow-ups for
the next tuning pass: child turn caps proved tight for verbose models
(several specialists hit 30 while still exploring), and one agent's
aggressive probing briefly knocked Juice Shop over — worth a
non-destructive reminder in the specialist prompt.

## Phase 3 — Browser + proxy ✅ (shipped 2026-08-16)

VulnEm is now a real web-app pentester: agents drive a headless browser,
all HTTP flows through a scope-enforcing proxy, and scans can run
authenticated without secrets ever touching a prompt.

What exists (on top of Phase 2):

- **Sandbox image** — Playwright + headless Chromium baked in at build time
  (system-wide browser path) so browser tooling works on internet-less lab
  networks. Sandbox gains `put_file`/`get_file` (tar) and routes exec'd HTTP
  through the proxy sidecar via env vars.
- **Browser tools** (`vulnem/tools/browser.py` + in-sandbox daemon) —
  `browser_navigate/click/fill/read_page/evaluate/screenshot`: one stateful
  Chromium context per agent (parallel specialists never share state),
  dialogs recorded as XSS *execution* evidence, screenshots persisted to
  `runs/<id>/artifacts/<agent>/` and cited as finding evidence. Host-side
  scope check refuses out-of-scope navigations and logs them.
- **Proxy sidecar** (`vulnem/proxy/`) — one mitmproxy container per scan on
  the sandbox network. Its addon (`scope_guard.py`) enforces an allowlist
  derived from `vulnem/scope.py`: out-of-scope requests → 403 / CONNECT
  denied, logged to the transcript + `run_dir/proxy-blocked.jsonl`. Every
  exchange is captured to a flow log the host reads back (get_archive) —
  scope is now prompt + network + proxy, three layers, none optional.
- **Proxy tools** — `list_requests`, `view_request`, `repeat_request`,
  `view_sitemap`. Replays are re-issued from the sandbox *through* the
  proxy with the live session, so they can never bypass scope.
- **Authenticated scans** (`--creds <file>`) — the host logs in (browser
  form / API / raw cookies) before any agent runs and seeds the session
  into every browser context plus a curl cookie jar / token header file.
  Credential values never enter a prompt or the transcript (only cookie
  names + method are recorded). Works for cookie-, token-, and
  localStorage-based auth (Juice Shop, DVWA verified live).
- **Second lab target** — DVWA (PHP) joins Juice Shop (Node) in
  `lab/docker-compose.yml` with creds examples; same skills, different
  stack.
- **Skills** — `browser_testing` pack (browser-vs-curl decision table,
  execution-proof workflow); `xss` + `recon` updated where the tools change
  the methodology.
- **Tests** — 29 new offline tests (64 total), `scripts/smoke_phase3.py`
  (9-check real-stack smoke), and the mock e2e extended to a 4th
  browser-driven specialist — all pass without an LLM key.

Exit criteria: MET (2026-08-16). The authenticated Juice Shop run
(`runs/20260815-195935-juice-shop-ea92`) found and PoC-validated XSS through
the browser tool with the proxy log as evidence — the DOM XSS via `#/search`
(JS source line + `browser_evaluate` execution proof + screenshot artifact +
6.6k captured flows). The stored flavor was browser-PoC'd on the DVWA run
(`runs/20260815-193336-dvwa-6251`: guestbook payload persisted, dialog
recorded, screenshot, 20.5k flows) alongside filed critical SQLi and command
injection — the current Juice Shop sanitizes its stored channels server-side
(verified), so its designed XSS surface is the DOM one the agent proved.
Full run accounting in TODO.md.

## Phase 4 — Polish: live UI, reports, white-box, CI ✅ (shipped 2026-08-16)

What exists (on top of Phase 3):

- **Live/replay TUI** (`vulnem/ui/`, `vulnem tui <run_dir>`) — a pure
  reducer (`state.py`) turns `transcript.jsonl` into view state (agent
  graph with statuses, tool/event stream, findings, flows, scope blocks,
  screenshots, mail); the Textual app renders it with paced replay
  (`--speed`, auto ~40s per run), instant mode, and `--follow` for
  tailing a live scan. Unknown event types degrade to a one-liner — the
  UI never lags the transcript schema.
- **Reports** — every scan writes `findings.sarif` (SARIF 2.1.0,
  validated against the OASIS schema; severity→level, CWE rule ids,
  `security-severity` for GitHub code scanning, stable partial
  fingerprints) and `report.pdf` (reportlab: severity table, per-finding
  detail, monospace PoC/evidence, fix-patch blocks).
  `vulnem report <run_dir>` re-exports both.
- **White-box mode** (`--source <dir>`) — source mounted read-only at
  `/home/pentester/source`; semgrep + a vendored ruleset baked into the
  sandbox image (build-time validated, works on internet-less lab
  networks). Workflow encoded in `skills/whitebox.md`: semgrep = leads,
  code-reading = tracing, dynamic validation = truth; findings carry
  `file`/`line` and a `fix_patch` unified diff. `lab/vulnapp` is the
  demo target: a stdlib-only app with six planted flaws (exact ground
  truth in `evals/ground_truth/vuln-app.json`).
- **CI mode** — `--ci` (headless, one `VULNEM_RESULT` line, exit 1 on
  findings), `--fail-on <severity>` threshold, `--scope-mode diff` +
  `--diff-file` (PR-sized scans: files/endpoints extracted from the
  diff, injected as a prompt-side narrowing directive — the three scope
  enforcement layers are untouched). `.github/workflows/ci.yml` runs
  lint+tests and the pr-check job: VulnEm scans this repo's own lab
  keylessly (scripted engine) and the job is green only when the
  fail-on-findings contract holds + SARIF/PDF artifacts verify.
- **Evals** (`vulnem/evals.py`, `scripts/eval.py`) — ground truth per
  target (vuln-app: 6 planted; juice-shop: 8 class-level; dvwa: 7
  module-level), a class+endpoint matcher (CWE canonicalization, title
  tokens, SPA fragment routes), and recall / FP-rate / cost scoring
  (tokens, turns, wall time). Scores recorded runs or launches fresh
  scans; tables land in `evals/results/`.

Exit criteria: MET (2026-08-16) — CI job + TUI + SARIF validated + eval
table; run accounting in TODO.md.

## Phase 5 — Interface-first web UI ✅ (shipped 2026-08-16)

`vulnem ui` (127.0.0.1:8756) — a local FastAPI app that drives and observes
the same engine the CLI does; no new scan semantics were invented, every
launch is a real `python -m vulnem.cli ...` subprocess.

- **W1 viewer** — runs list, run page (agent tree + live SSE stream +
  findings, reusing the TUI's reducer through `serialize`/`tail` helpers),
  structured report pages, whitelisted raw-file and artifact routes.
- **W2 scan driver** — new-scan form (presets + advanced options), the
  typed-host authorization gate with exact CLI parity (`scans.py` is the
  pure logic, unit-tested), and a `JobManager` running CLI subprocesses
  with streamed logs, run-dir discovery, job pages and stop.
- **W3 setup wizard** — `/setup` renders the doctor checks in the browser
  (`checks.py`, cached 30s so page loads stay fast when Docker is down)
  with one-click fixes: a model + API-key editor for `.env` (`envfile.py`
  upsert preserves comments/order; key values are write-only — never
  rendered or logged), sandbox-image build and the safe demo as tracked
  jobs (double-launch guard; demo disabled until docker/image/key pass),
  and a setup-incomplete banner on the runs list.
- **StudioBlank redesign + dark mode** — the whole interface was restyled to
  the repo's `DESIGN.md` design system (light `#FAFAFA`, strictly flat, 0px
  radius everywhere, monochrome Inter + IBM Plex Mono, semantic color only
  as status; fonts via local fallbacks — the app stays CDN-free/offline).
  A Heroicons sun/moon toggle in the top bar swaps the CSS custom-property
  tokens to a faithful dark inversion (`[data-theme="dark"]`), persisted in
  localStorage with a pre-paint `<head>` script (no flash). Chrome polish:
  favicon, skip-link, active-nav states, branded 404 page, tabular numerals,
  reduced-motion support. Functionality, routes, and the JS contracts were
  untouched — 170 tests stayed green throughout.

---

## Cross-cutting rules

- **Safety**: authorized targets only; `demo` stays on an isolated internal
  Docker network; scope is enforced in code, not just prompts.
- **Cost discipline**: every run logs token/turn usage; budgets are
  first-class (Phase 2).
- **Transcript is the product**: everything the UI will ever show must be
  in `transcript.jsonl` — keep it complete and stable.
- **Skills iterate faster than code**: new vulnerability knowledge lands as
  markdown, never as hardcoded Python.
