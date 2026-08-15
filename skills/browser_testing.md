---
name: browser_testing
description: Browser-driven testing methodology — when to use browser_* tools vs curl, XSS execution proof, authenticated flows, proxy-assisted workflow
---

# Browser-Driven Testing

You control a headless Chromium (`browser_navigate`, `browser_click`,
`browser_fill`, `browser_read_page`, `browser_evaluate`,
`browser_screenshot`) with a STATEFUL session: cookies and localStorage
persist between your calls, and (on authenticated scans) the session arrives
already logged in. Everything the browser sends is captured by the proxy —
inspect it with `list_requests` / `view_request` / `view_sitemap` and replay
with `repeat_request`.

## 1. Choose the right tool

| Situation | Use |
| --- | --- |
| JSON API, quick probe, raw headers | curl via exec_command |
| Page whose content is built by JavaScript (SPA) | browser_navigate + browser_read_page |
| Input lives in a form/UI flow (no clean API) | browser_fill + browser_click |
| Proving code EXECUTION (XSS) | browser_navigate, then browser_read_page (dialogs) or browser_evaluate |
| Visual/contextual evidence for a finding | browser_screenshot |
| Replaying a captured request with tweaks | repeat_request |

Rule of thumb: if `curl` output looks empty or skeleton-like while the app
clearly has content, the page is JS-rendered — switch to the browser.

## 2. Workflow

1. `browser_navigate` to the page. Check `status` + `title`.
2. `browser_read_page` — inventory: visible text, links, forms/inputs, and
   any dialogs recorded so far. This is your DOM ground truth.
3. Act: `browser_fill` the interesting field(s), `browser_click` submit, or
   drive the URL directly (`browser_navigate <url>?q=<payload>`).
4. Observe the RESULT page with `browser_read_page` again — diff mentally
   against step 2.
5. When something interesting happens, capture evidence:
   `browser_screenshot` (artifact path goes in the finding) and
   `list_requests` / `view_request` for the exact exchange.

Selectors are CSS (`#id`, `.class`, `input[name=q]`, `text=` not supported —
use attributes). `browser_read_page`'s `inputs` list tells you what
name/id/type the page actually has — use it instead of guessing.

## 3. XSS execution proof (the reason this tool exists)

Reflection in HTML (curl) proves injection; it does NOT prove execution.
For execution:

1. Inject a payload with an observable side effect, e.g.
   `<img src=x onerror="window.__xss=1">` or `alert(document.domain)`.
2. `browser_navigate` to the page where the payload renders.
3. Prove it ran — either:
   - `browser_read_page` shows a recorded `dialogs` entry (`alert()` fired), or
   - `browser_evaluate` `window.__xss` returns `1`.
4. `browser_screenshot` the rendered payload as visual evidence.

A dialog entry or a flipped marker IS execution evidence — file the finding
with both the curl-level reflection AND the browser-level execution proof.

## 4. Stored XSS specifically

Store via the app's own flow (form or API — the API is usually cheaper:
find it in `view_sitemap`), then render via the browser where the app shows
it back, then follow §3. Sequence: store → navigate → read_page/evaluate →
screenshot.

## 5. Authenticated testing

If the scan is authenticated, your browser context AND curl already carry the
session: `-b /home/pentester/cookies.txt`, plus `-H
@/home/pentester/.vulnem/auth-header.txt` when the target uses token auth
(never print the file contents — reference it). Verify cheaply with
`browser_read_page` (logged-in UI) or a whoami-style endpoint via
`repeat_request`. Test the AUTHORIZED functions: IDOR (swap ids in URLs via
browser or repeat_request), privilege-boundary pages, stored payloads in
profile fields.

## 6. Proxy-assisted analysis

- `view_sitemap` after browsing = the endpoint map of everything YOU did.
- `list_requests {q: ...}` + `view_request {id}` to study one exchange
  (note: Authorization/Cookie are redacted in the log — replay instead).
- `repeat_request {id, modifications: {body: ...}}` re-sends a captured
  request with your changes, through the same scope-enforced proxy, with the
  live session. Perfect for parameter tampering and PoC confirmation.

## Rules

- The browser session is YOURS only (per-agent) — state from other agents
  never leaks in, and yours never leaks out.
- Keep navigation in scope; the tool refuses out-of-scope hosts and logs it.
- Prefer `domcontentloaded` speed: don't add waits; the tools wait for
  network idle already.
- If a selector fails, `browser_read_page` and pick the real one. Don't
  retry the same selector more than twice.
