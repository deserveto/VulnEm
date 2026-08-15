# VulnEm — Build Plan

Autonomous AI penetration-testing agent for **authorized** security testing,
built Strix-style: LLM agents + an isolated Docker sandbox full of security
tooling, driven through recon → testing → validated PoC → report.

This is the living roadmap. Current state: **Phase 1 shipped**, Phase 2 next.

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

## Phase 2 — Coordinator + specialist agents (the "graph of agents")

Turn the single agent into an addressable multi-agent graph, Strix's core
trick. This is the biggest phase; break it into the steps in `TODO.md`.

New module `vulnem/agents/`:

- **`coordinator.py`** — single owner of graph state:
  statuses (`running|waiting|completed|stopped|crashed|failed`),
  parent/child tree, per-agent mailboxes (queue + wake event — a message to
  a parked agent revives it), asyncio tasks, JSON snapshot/restore.
- **Root agent** — orchestrator; system prompt forbids hands-on testing.
  New tools: `create_agent`, `view_agent_graph`, `send_message_to_agent`,
  `wait_for_agents`, `stop_agent`.
- **Child agents** — same hands-on toolset as today's Phase 1 agent, plus
  `agent_finish` which files a structured completion report (status,
  summary, findings, recommendations) into the parent's session.
- **Budget control** — per-agent turn caps, scan-wide spend/turn budget,
  pause + extend (user can top up mid-run).

Supporting work:

- Findings upgrade: severity field + CVSS vector, cross-agent dedupe
  (same endpoint + same class collapse to one finding with merged evidence).
- Inter-agent messaging format: `[Message from <name> | type | priority]`
  injected as user-role items — no new transport needed.
- Skills expansion toward ~12 packs: add `idor`, `ssrf`, `auth_jwt`,
  `ssti`, `file_upload`, `open_redirect`, `prototype_pollution`,
  `coordination/root_agent` (the delegation playbook).
- Snapshot/resume: coordinator state + agent sessions to disk; `vulnem resume`.
- Transcript upgrade: per-agent streams in `transcript.jsonl` so the future
  UI can render the live graph.

Exit criteria: a Juice Shop demo run where the root agent spawns ≥3
specialists in parallel, dedupes overlapping findings, and produces a
report at least as good as Phase 1's single-agent report, at comparable
total cost.

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
