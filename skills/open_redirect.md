---
name: open_redirect
description: Open redirect testing — parameter hunting, bypass lists, token-leak proof
---

# Open Redirect (CWE-601)

## 1. Hunt redirect parameters

Crawl + endpoint map: `?url=`, `?next=`, `?redirect=`, `?return=`,
`?returnTo=`, `?continue=`, `?goto=`, `?target=`, `?dest=`; login flows
(`/login?next=`), logout, language switchers, marketing links, SSO
callbacks. Also server-side redirect chains: 30x Location headers that
contain user input.

```bash
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  '<target>/login?next=http://canary.example/evil'
```

`redirect_url` pointing off-origin = candidate.

## 2. Confirm with a real browser-grade check

The bar: does the SERVER issue a redirect whose Location is attacker
controlled?

```bash
curl -sI '<target>/redirect?url=https://example.org/' | grep -i '^location'
```

If the value is reflected into Location (or into a meta-refresh / JS
`window.location` in the body), confirm exact-match control:
`https://example.org/vulnem-canary-<rand>`.

## 3. Filter bypasses (when a whitelist exists)

Host part tricks, if the app validates only a substring:

```
https://trusted.com@evil.example/          (userinfo confusion)
https://trusted.com.evil.example/          (subdomain of attacker)
//evil.example                             (protocol-relative)
https://evil.example#trusted.com           (fragment)
https://evil.example\@trusted.com          (backslash, some parsers)
https://trusted.com/redirect?url=evil      (open redirect chaining)
\/\evil.example and https:/\/\evil.example (slash parsers)
```

## 4. Impact analysis

- Token/secret leakage: does the redirect URL carry a code/token
  (`/sso/callback?code=...&next=ATTACKER`)? → high/critical (OAuth token
  theft).
- Pure redirect to arbitrary origin (phishing enabler) → low/medium.
- Same-site-only redirect → not a finding.

## 5. Validation bar

- Evidence: the request + the 30x Location header (or rendered redirect
  JS/meta tag) pointing to your canary host.
- PoC: the exact URL. Severity from step 4; phishing-only redirects max
  out at medium.
