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

## Phase 3 — Browser + proxy ✅ DONE (2026-08-16)

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

## Phase 4 — Polish ✅ DONE (2026-08-16)

- [x] Live TUI (Textual) over transcript.jsonl: agent graph + tool stream +
      findings (`vulnem/ui/state.py` pure reducer — every event type has a
      home, unknown types degrade to a one-liner; `vulnem tui <run_dir>`
      with paced replay / `--speed 0` instant / `--follow` for live scans;
      headless pilot tests + reducer tests against the two richest
      recorded runs)
- [x] SARIF report output (OASIS-schema-validated, severity→level, CWE
      rule ids, GitHub security-severity, stable fingerprints) + PDF
      export (reportlab) + `vulnem report` re-export cmd; both written
      automatically at scan end
- [x] White-box mode: `--source <dir>` read-only mount, semgrep + vendored
      ruleset in the sandbox image (build-validated, offline-usable),
      `skills/whitebox.md` methodology, findings carry file:line +
      fix_patch (rendered in report.md/PDF, region-mapped in SARIF);
      `lab/vulnapp` planted-flaw demo target (6 flaws, exact ground truth)
- [x] CI mode: `--ci` headless + VULNEM_RESULT line, `--fail-on` severity
      threshold, `--scope-mode diff`/`--diff-file` PR-sized scans
      (prompt-level focus; scope enforcement layers never weakened);
      `.github/workflows/ci.yml` lint+test job + keyless pr-check job that
      runs VulnEm on this repo's own lab and verifies fail-on-findings +
      SARIF/PDF artifacts (mock e2e tightened to require exit 1)
- [x] Eval harness: `scripts/eval.py` + `vulnem/evals.py` — ground truth
      (vuln-app 6 planted, juice-shop 8 class-level, dvwa 7 modules),
      class+endpoint matcher, recall/FP/cost tables to evals/results/

Real-run accounting (2026-08-16, hcnsec relay — flash = `openai/auto`
(agnes-2.5-flash), pro = `openai/DeepSeek-V4-Pro` (nemotron-3-ultra-550b),
all authenticated + proxied + `--budget`-bound; full tables in
`evals/results/`):

- `runs/20260815-205914-vuln-app-e129` (flash, white-box, 100 turns):
  **100% recall on all 6 planted flaws** in 4 min / 672k tokens; 8/9
  findings carry file:line + fix patches; cross-agent dedupe merged the
  whitebox-analyst + injection overlaps; root followed the whitebox
  nudge and spawned a dedicated source-analysis specialist.
- `runs/20260815-210529-juice-shop-9e7b` (flash, 200 turns): 25% recall /
  50% FP — the failure mode the provider warning predicted: 2 specialists
  hit 30-40-turn caps without filing, root finished while injection was
  still live (force-stopped, nothing filed), and the JWT specialist filed
  3 NEGATIVE results as findings → prompt fix committed (negative results
  are not findings).
- `runs/20260816-050712-juice-shop-344a` (flash, 200 turns, child caps 55):
  **prompt fix confirmed** — 50% recall / no negative-results-as-findings;
  13 findings, all claims of real issues (the 69% matcher FP rate is mostly
  below-GT-granularity observations: missing Referrer-Policy/HSTS, JWT
  payload data, /api/Challenges exposure — compact-GT cost, not noise).
- `runs/20260815-211626-juice-shop-8a32` (pro, 200 turns): 25% recall /
  **0% FP** — both SQLis (login auth-bypass + search) properly validated;
  but sequential recon ate 90 turns and the budget capped coverage at 193
  turns. Pro is precise and slow (~30 min/run).
- `runs/20260815-214757-dvwa-c52f` (pro, 300 turns): 14% recall / 0% FP —
  validated SQLi only; specialists hit the per-child caps root assigned
  (35) mid-validation and filed nothing (the Phase 3 file-immediately
  lesson again: root's `create_agent max_turns` choice overrides
  VULNEM_CHILD_MAX_TURNS).
- Historical poolside baselines (same GT): juice ea92 38%/40%, juice
  a079 25%/0%, dvwa-6251 43%/0%, 69ce 12%/75%.

Provider verdict: flash = fast/cheap/broad but loose (needs the negative-
findings guard + tighter root discipline); pro = precise but budget-hungry
— give it budget 300+ and child caps 55+ for coverage. White-box + small
targets are flash's sweet spot. Tuning knobs for real runs:
VULNEM_CHILD_MAX_TURNS=55, VULNEM_MAX_TOTAL_TOKENS=12000000.

Phase 4 exit criteria: MET — CI pr-check job live, TUI replays recorded
runs, SARIF validated against the OASIS schema, eval table from multiple
targets.

## Parking lot (unscheduled)

- [ ] Local-model support validation (Ollama) for air-gapped runs
- [ ] Multi-target scans from a file
- [ ] Web viewer if Textual limits bite
