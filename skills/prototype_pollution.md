---
name: prototype_pollution
description: Prototype pollution — client and server side, sink hunting, benign-impact canaries
---

# Prototype Pollution (CWE-1321)

## 1. Understand the two sides

- **Client-side**: JS in the target's frontend merges attacker input
  (`JSON.parse(location.hash)`, `Object.assign`, old jQuery `$.extend(true,
  {}, user)`), polluting `Object.prototype` in the victim's browser.
- **Server-side (Node)**: the backend merges user JSON into objects
  (`lodash.merge`, `defaultsDeep`, custom recursive merge) — often
  exploitable to RCE via gadget properties (`child_process`, `status`,
  `shell`).

## 2. Client-side detection

In the page's JS: find merge sinks first (fetch the bundle, `grep -o
'extend\|merge\|Object.assign' app.js`). Probe hash/query inputs:

```
https://<target>/#?__proto__[canary]=VULNEM
https://<target>/?__proto__[canary]=VULNEM
https://<target>/?constructor[prototype][canary]=VULNEM
```

Then in the browser console (or headless check):
`Object.prototype.canary` — "VULNEM" = polluted. Without a browser, check
for DOM-observable side effects (broken rendering, altered links).

## 3. Server-side detection

```bash
curl -s -X POST <target>/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"__proto":{"canary":"VULNEM"},"key":"value"}'
# then observe: does ANY subsequent response or behavior change?
curl -s <target>/api/settings | head -c 300
```

Signals: `{"canary":"VULNEM"}` appearing in later objects, 500s after
pollution (merge broke), changed headers/error formats. JSON bodies via
files per the usual quoting rule.

## 4. Escalate to impact (the finding needs a sink)

- Client: pollute a DOM XSS gadget — e.g. `__proto__[srcdoc]` on an
  iframe, `__proto__[html]` on a render call, trusted-types bypasses.
  Report as prototype-pollution → stored/reflected XSS with the chain.
- Server: classic gadgets (Node): `{"__proto":{"status":510}}` (visible
  status change), `{"__proto":{"shell":"...","NODE_OPTIONS":"--require..."}}`
  RCE chains via child_process.spawn — in a lab, proving ONE observable
  gadget (status change) is enough; do not push destructive RCE.

## 5. Validation bar

- Evidence: pollution request + the observable effect (console output
  pattern, changed response, status-code gadget).
- A merge sink with no reachable gadget = report low/medium "server-side
  prototype pollution in <endpoint>, no gadget identified".
- Coordinate with the xss specialist for DOM chains — one finding per
  distinct sink chain, merged automatically if same URL+class.
