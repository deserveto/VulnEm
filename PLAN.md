# VulnEm — Build Plan

Autonomous AI penetration-testing agent for **authorized** security testing,
built Strix-style: LLM agents + an isolated Docker sandbox full of security
tooling, driven through recon → testing → validated PoC → report.

This is the living roadmap. Current state: **Phase 2 shipped**, Phase 3 next.

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
| Browser | Playwright headless Chromium in sandbox | Phase 3 |
| Proxy | mitmproxy (Python-scriptable) | Phase 3 |
| UI | Textual TUI or local web viewer over `transcript.jsonl` | Phase 4 |
| Reports | `report.md` + `findings.json` (done) → SARIF, PDF | Phase 4 |
| Test targets | OWASP Juice Shop (done) → DVWA, vulhub | Phase 3–4 |

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

Pending: a real-LLM `vulnem demo` to compare cost/quality vs the Phase 1
runs (needs an API key) — the exit criterion for closing Phase 2 fully.

## Phase 3 — Browser + proxy (web-app pentester, not just "agent with nmap")

- **Playwright tool** (`vulnem/tools/browser.py`): headless Chromium inside
  the sandbox; navigate, click, fill, screenshot (screenshots flow into the
  transcript → evidence). Unlocks XSS, CSRF, clickjacking, auth-flow testing.
- **mitmproxy integration** (`vulnem/tools/proxy.py`): agent tools
  `list_requests`, `view_request`, `repeat_request`, `view_sitemap`;
  traffic from sandbox routed through the proxy.
- **Network-layer scope enforcement**: proxy allowlist derived from
  `vulnem/scope.py` — out-of-scope requests blocked and logged, closing
  the prompt-leak gap.
- **Grey-box authenticated scans**: `--instruction` / credentials file;
  session cookies handled via the proxy/browser, not the prompt.
- Second lab target: DVWA or a vulhub compose (different tech stack to
  prove skills generalize).

Exit criteria: an authenticated Juice Shop run that finds and PoC-validates
a stored-XSS via the browser tool, with the proxy log as evidence.

## Phase 4 — Polish: live UI, reports, white-box, CI

- **Live viewer** over `transcript.jsonl`: agent graph (nodes = agents,
  status colors), tool-call stream, findings panel. Textual TUI first
  (`vulnem tui`); local-only web viewer only if TUI limits bite.
- **Reports**: SARIF output (CI-friendly), PDF export, severity summary.
- **White-box mode**: `--source <dir>` mounts the repo into the sandbox,
  semgrep + agent code-reading; findings link file:line and carry a fix
  patch (Strix's `apply_patch` pattern).
- **CI mode**: headless, non-zero exit on findings, `--scope-mode diff`
  for PR-sized scans.
- **Evals**: benchmark scripts against Juice Shop + vulhub targets —
  finding recall, false-positive rate, cost per run; guard against prompt
  regressions (the a72445a lesson systematized).

Exit criteria: a PR-check CI job that runs VulnEm on this repo's own lab
and fails on findings.

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
