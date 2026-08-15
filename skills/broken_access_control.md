---
name: broken_access_control
description: IDOR, privilege escalation, and auth-bypass testing — the highest-value class
---

# Broken Access Control (IDOR, privilege escalation, auth bypass) (CWE-639/284)

This class is #1 on OWASP Top 10 and yields the highest-severity findings.
It needs at least two identities.

## 1. Get two accounts

Register/observe two users (e.g. `attacker@test` and `victim@test` — in labs,
use the seeded accounts; Juice Shop has known demo credentials if listed in
the target's docs/robots). Log in as each via API and store their tokens:

```bash
curl -s -X POST <target>/rest/user/login -H 'Content-Type: application/json' \
  -d '{"email":"attacker@test.io","password":"x"}' | tee /tmp/attacker.json
# extract token/BID with jq:  jq -r '.authentication.token' /tmp/attacker.json
```

## 2. IDOR hunt (object references)

1. As victim, list your resources (orders, basket, memories, receipts) and
   note the numeric IDs.
2. As attacker, request VICTIM's IDs directly:

```bash
curl -s <target>/api/BasketItems/1 -H "Authorization: Bearer $ATTACKER_TOKEN"
curl -s <target>/rest/basket/1 -H "Cookie: token=$ATTACKER_TOKEN"
```

3. Also flip the direction (victim reads attacker's) — either direction
   proves the flaw. Try +/- 1 around your own IDs.

## 3. Privilege escalation

- Find admin surface from recon (`/administration`, `/api/admins`, admin
  menu items hidden client-side but present in JS/HTML).
- Request it with a NORMAL user token. Client-side hiding + server 200 =
  finding.
- Try role-tampering at registration/profile update:
  `{"email":"a@b.c","password":"x","role":"admin"}` (mass assignment).

## 4. Auth bypass

- Endpoints that answer correctly with NO token at all.
- JWT in cookie? Try `alg:none` and unsigned-token tricks, `kid` injection —
  only if the token structure suggests it (decode first:
  `echo $T | cut -d. -f2 | base64 -d 2>/dev/null | jq`).

## 5. Validation bar

Evidence MUST include both sides: the request as attacker + victim's data in
the response (or admin data with a non-admin token). Record which user,
which object ID, and the exact curl. One clean proof beats five maybes.
