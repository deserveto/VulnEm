---
name: whitebox
description: Source-assisted assessment when the target's code is mounted — semgrep first pass, code reading, dynamic validation, file:line findings with fix patches
---

# White-Box Assessment

You have something black-box testers don't: the target's source, mounted
READ-ONLY (typically at `/home/pentester/source`). Source access changes
the workflow, not the standards — every finding still needs dynamic proof.

## Workflow

1. **Orient** (2-3 commands, cheap):
   ```
   find /home/pentester/source -type f | head -50
   rg -n "route|@app|def do_|handler" /home/pentester/source --max-count 50
   ```
   Map files to the routes you already know from recon. Identify the
   framework/stack before reading deep.

2. **Semgrep first pass** (vendored rules — no internet needed):
   ```
   semgrep --config /opt/semgrep-rules --json /home/pentester/source \
     > /tmp/semgrep.json
   jq -r '.results[] | "\(.check_id) \(.path):\(.start.line) \(.extra.message)"' /tmp/semgrep.json
   ```
   These rules flag SINKS (SQL string-building, shell=True, path joins,
   hardcoded secrets, eval, SSTI). Semgrep output is a lead list, never a
   finding — reachability and exploitability are your job.

3. **Trace each lead** in the code: find where the parameter enters
   (route handler / query string), confirm no sanitization between entry
   and sink. `rg -n "<function-name>" -A 20` beats reading whole files.

4. **Validate dynamically** against the live target. The code may be dead,
   guarded elsewhere, or the sink may be unreachable with remote input.
   A finding without a reproduced PoC is a hypothesis, not a finding.

5. **File with precision**:
   - `file` + `line` must point at the vulnerable statement (relative to
     the source root), not the function start.
   - `fix_patch`: a minimal unified diff against the real code —
     parameterize the query, `shell=False` with a list, `shlex.quote`,
     `os.path.basename`, move the secret to env. Copy the actual context
     lines from the source so the patch applies.
   - Evidence: BOTH the source line (with path:line) and the dynamic
     command + response that proves exploitability.

## Fix patterns that hold up

| Flaw | Fix sketch |
| --- | --- |
| SQL string-building | parameterized query: `execute("... WHERE name LIKE ?", (f"%{q}%",))` |
| `shell=True` with f-string | `subprocess.run(["ping","-n","1", host], shell=False)` — validate host against an allowlist regex first |
| Path traversal | `name = os.path.basename(name)` + reject `..`, or `os.path.realpath` containment check |
| Hardcoded secret | read from `os.environ`, document rotation |
| Debug endpoint | gate behind auth/config flag, redact secrets + env |

## Judgment calls

- Generated/vendored code (node_modules, dist/, minified bundles): skip
  unless the flaw is reachable from app code.
- Test fixtures and docs with fake secrets are not findings — check
  whether the secret is loaded at runtime.
- If the source doesn't match the running target's behavior (stale
  mount, different build), trust the live target and note the mismatch.
