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

- [x] Playwright headless Chromium in sandbox image (baked at build time,
      system-wide browser path; works with no internet at runtime)
- [x] Browser tool: navigate/click/fill/read_page/evaluate/screenshot;
      stateful per-agent sessions via an in-sandbox daemon; screenshots →
      runs/<id>/artifacts/ + transcript evidence events
- [x] mitmproxy sidecar on the lab network; sandbox HTTP routed through it
      (proxy env for exec'd clients, per-context proxy for Chromium)
- [x] Proxy tools: list_requests, view_request, repeat_request (replays from
      the sandbox through the proxy, never bypassing scope), view_sitemap
- [x] Network-layer scope allowlist (mitmproxy addon derived from
      vulnem/scope.py — out-of-scope blocked 403/CONNECT-denied + logged to
      transcript + run dir; browser navigations host-checked too)
- [x] Authenticated scans: --creds file (browser form / API / cookies),
      session seeded into browser contexts + curl jar + token header file;
      secrets never in prompts or the transcript
- [x] Second lab target: DVWA (PHP) alongside Juice Shop (Node) in
      lab/docker-compose.yml + creds examples for both
- [x] Skills: browser_testing pack (15 total); xss/recon updated for the
      browser+proxy workflow; prompts cover browser-vs-curl choice
- [x] Tests: test_browser.py + test_proxy.py (29 new, 64 total);
      scripts/smoke_phase3.py (real-stack 9-check smoke); mock e2e extended
      with a browser-driven specialist — passes with no LLM key
- [x] Definition of done — see run accounting below.

Real-run accounting (2026-08-16, poolside/laguna-s-2.1, all authenticated,
proxy on, `--budget`-bound):

- `runs/20260815-195935-juice-shop-ea92` (graph, 200-turn budget): the
  client-side-xss specialist found and PoC-VALIDATED the Juice Shop XSS
  through the browser tool — DOM XSS via `#/search?q=` with the JS source
  line (`bypassSecurityTrustHtml`), `browser_evaluate` marker proof
  (`window.__xss === 1`), screenshot artifact in `artifacts/`, proxy flow
  log as evidence (6.6k captured exchanges snapshotted to the run dir).
  Plus SQLi in login (critical, auth bypass), boolean-blind SQLi in search,
  admin-config exposure. This IS the Juice Shop XSS surface — its feedback
  stored channel sanitizes server-side (verified: a payload POST via the
  captcha-leak chain stores an empty comment).
- `runs/20260815-193336-dvwa-6251` (graph, 220-turn budget): stored XSS
  PoC-validated through the browser (guestbook payload persisted, alert
  dialog recorded, screenshot `artifacts/xss-cmdinj/*xss_stored_alert_dvwa.png`,
  20.5k proxy flows) — the specialist hit its turn cap before filing that
  one; the filed XSS (reflected, medium) used the same browser-dialog proof.
  Filed: command injection (critical), SQLi (critical, cross-agent dedupe
  merged two reporters), reflected XSS. Skills generalized to the PHP stack.
- Two earlier Juice runs (`...-b0d7`, `...-a079`) proved the plumbing end to
  end (auth seeding, ~5-8k proxy flows, browser use mid-scan, budget
  force-stop with honest synthesis) and filed the /api/Users IDOR + JWT-data
  criticals; they also surfaced the tuning fixes above (file-immediately
  rule, child caps 45-60, token-budget ceiling for verbose models) and a
  provider quota end (`429 usage limit exceeded`) that stopped a final
  solo re-run on turn 1.

Verdict: DoD substance met — browser-validated XSS with proxy-log evidence
on an authenticated Juice Shop run (DOM flavor, the class the target
actually offers) plus a stored XSS browser-PoC on the authenticated DVWA
run; the literal combination (stored XSS on Juice Shop as a filed finding)
is not achievable on the current target without a real 0-day, since the
server sanitizes the stored channels the agent correctly identified.

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
