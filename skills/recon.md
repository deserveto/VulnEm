---
name: recon
description: Reconnaissance and attack-surface mapping workflow — always do this first
---

# Recon & Attack Surface Mapping

Goal: build a map of the target (stack, endpoints, params, auth surfaces) that
drives prioritized testing. Recon quality decides the whole scan.

## Phase 1 — Fingerprint the stack

```bash
whatweb <target>                       # server, framework, CMS hints
curl -si <target> | head -40           # headers: server, x-powered-by, cookies, CSP
curl -s <target>/robots.txt
curl -s <target>/sitemap.xml | head -50
```

Note security-relevant headers (missing CSP / X-Frame-Options, verbose server
banner, cookie flags: HttpOnly/Secure/SameSite). Those are findings themselves
(severity low/info) — record them but keep moving.

## Phase 2 — Discover endpoints

```bash
# Crawl (JS-aware):
katana -u <target> -d 3 -silent | sort -u > /tmp/crawl.txt

# Content discovery with ffuf (filter by size to cut noise):
ffuf -w /usr/share/wordlists/common.txt -u <target>/FUZZ -mc all -fs 0 -t 20

# API route hints:
curl -s <target>/api/ | head -100
curl -s <target>/openapi.json | head -100
curl -s <target>/swagger.json | head -100
```

## Phase 3 — Inventory and prioritize

Consolidate into `/tmp/endpoints.txt` (method + path + params + auth required?).
Then rank surfaces by expected value:

1. Authentication / registration / password reset
2. Admin or internal routes reachable without auth
3. REST/GraphQL APIs taking user input (search, profile, feedback, file upload)
4. Redirect parameters (`?url=`, `?redirect=`)
5. Everything else

## Rules

- ONE command per exec call; if output is huge, redirect to /tmp and grep it.
- Verify discovered routes exist (`curl -s -o /dev/null -w '%{http_code}' <url>`)
  before spending turns on them.
- Record the map (write it to /tmp/attack-surface.md with `think` or a file)
  so later turns can consult it.
- Move to targeted testing once you have the top 5-10 surfaces mapped. Do not
  enumerate forever.
