# VulnEm — TODO

Working checklist. Detail and rationale in `PLAN.md`. Mark with `[x]` when
done; add new discoveries at the bottom of the phase they belong to.

## Phase 1 — Single agent ✅ DONE (2026-08-15)

- [x] Project scaffold, pyproject, README, .env config
- [x] Kali-based sandbox image (`vulnem build`)
- [x] Scope enforcement (`vulnem/scope.py`) + tests
- [x] Docker sandbox lifecycle + exec (`vulnem/sandbox/docker.py`)
- [x] Agent loop with tools: exec_command, read_skill, report_finding, think, finish
- [x] CLI: scan / demo / build / doctor / skills
- [x] Findings + report.md + findings.json + transcript.jsonl
- [x] Juice Shop lab (`lab/docker-compose.yml`) + `vulnem demo`
- [x] 5 skills (recon, sql_injection, xss, command_injection, broken_access_control)
- [x] Tests + mock e2e; 7 real runs; prompt tuned from transcript

## Phase 2 — Coordinator + specialist agents ✅ DONE (2026-08-16)

Foundation:

- [x] Extract `AgentRun`/session handling out of `agent/loop.py` so multiple
      agents can run concurrently on one sandbox
      (`vulnem/agents/session.py` — async loop, exec/LLM in worker threads)
- [x] `vulnem/agents/coordinator.py`: register/status/parent-child state,
      asyncio task per agent (statuses: running|waiting|completed|stopped|crashed|failed)
- [x] Mailboxes: per-agent queue + wake event; messages injected into the
      target's session as `[Message from <name> | type | priority]` user items
- [x] Root agent prompt: delegation-only playbook (never touch the target);
      the substance of Strix's root-agent skill lives in
      `skills/coordination/root_agent.md`
- [x] Graph tools for root: `create_agent`, `view_agent_graph`,
      `send_message_to_agent`, `wait_for_agents`, `stop_agent`
- [x] `agent_finish` on children: structured completion report
      (status/summary/findings/recommendations) into parent session
- [x] Wait/park semantics: `wait_for_agents` blocks until children report;
      no polling loops (one wait, then react; messages revive a parked waiter)

Budget + resilience:

- [x] Per-agent turn caps + scan-wide budget; pause/extend
      (`vulnem scan --budget`, `vulnem resume --extend-turns`)
- [x] Child crash isolation: mark crashed, notify parent, scan continues
- [x] Coordinator snapshot/restore to `runs/<id>/state.json`; `vulnem resume`

Reporting upgrade:

- [x] Severity + CVSS vector on findings
- [x] Cross-agent dedupe (endpoint + class → one finding, merged evidence)

Skills expansion (14 packs total):

- [x] idor, ssrf, auth_jwt, ssti, file_upload, open_redirect,
      prototype_pollution, business_logic

Transcript:

- [x] Per-agent attribution in `transcript.jsonl` (agent_ctx, parent_id,
      status transitions) — everything the future UI needs

Definition of done: MET (2026-08-16). Mock e2e (no LLM key) proves root
spawns 3 specialists in parallel, dedupes overlapping findings, report ≥
Phase 1 format. Real run (`runs/20260815-181256-...`, 150-turn budget):
root spawned 5 specialists in parallel, parked in wait_for_agents, handled
2 mid-run failures, and reported a validated critical SQLi (+CORS/CSP)
with CVSS + attribution. Tuning notes for Phase 3: child turn caps tight
for verbose models; fragile-target probing reminder needed.

## Phase 3 — Browser + proxy ← CURRENT

- [ ] Playwright headless Chromium in sandbox image
- [ ] Browser tool: navigate/click/fill/screenshot; screenshots → transcript evidence
- [ ] mitmproxy sidecar; sandbox traffic routed through it
- [ ] Proxy tools: list_requests, view_request, repeat_request, view_sitemap
- [ ] Network-layer scope allowlist (block + log out-of-scope)
- [ ] Authenticated scans: credentials file, session via proxy/browser
- [ ] Second lab target (DVWA or vulhub) to prove skills generalize
- [ ] Definition of done: authenticated stored-XSS found + PoC'd via browser,
      proxy log as evidence

## Phase 4 — Polish

- [ ] Live TUI (Textual) over transcript.jsonl: agent graph + tool stream + findings
- [ ] SARIF report output; PDF export
- [ ] White-box mode: `--source`, semgrep, file:line findings, fix patches
- [ ] CI mode: headless, exit-code-on-findings, diff-scoped PR scans
- [ ] Eval harness: recall/FP/cost benchmarks on Juice Shop + vulhub

## Parking lot (unscheduled)

- [ ] Local-model support validation (Ollama) for air-gapped runs
- [ ] Multi-target scans from a file
- [ ] Web viewer if Textual limits bite
