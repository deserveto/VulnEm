---
name: auth_jwt
description: JWT and session-token attacks — decode, weak secrets, alg confusion, claim tampering, expiry
---

# JWT / Token Authentication Testing (CWE-347, CWE-287)

## 1. Collect tokens

Register/login; capture the token from the response, cookies, and
Authorization headers on subsequent requests. Note where each token type
works (`/api/whoami`).

```bash
TOKEN=$(curl -s -X POST <target>/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"tester@local.test","password":"x"}' | jq -r .authentication.token)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq   # decode payload
```

Record the header too (`cut -d. -f1`): algorithm, kid, typ.

## 2. Weak signing secret

```bash
# Try the obvious ones against the real token:
for secret in secret password jwt-secret <target-host> vulnem null none ''; do
  printf '%s' "$(echo "$TOKEN" | cut -d. -f1.2)" | \
    openssl dgst -sha256 -hmac "$secret" -binary | base64 | tr -d '=' | tr '/_' '\\/' 
  # compare against the token's third segment
done
```

Faster: `hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt`
(time-boxed, lab-only). A cracked secret lets you forge any identity →
proof = a forged admin token that `/api/whoami` accepts.

## 3. Claim tampering

- `alg: none`: strip the signature, set header alg to none, modify payload
  (`"role":"admin"`, `"email":"admin@..."`), send without signature.
- `alg` confusion (RS256→HS256): if the server verifies HS256 using the
  PUBLIC key as HMAC secret: `openssl req` for a keypair? No — fetch the
  public key (jwks endpoint) and sign HS256 with its PEM bytes.
- Expiry/claims: drop `exp`, set `"exp": 9999999999`, change `sub`/`uid` to
  another user id (overlaps idor — coordinate with that specialist).
- `kid` injection: header `kid` used in shell/fs paths — try `kid`:
  `../../dev/null`, or SQLi in kid (rare, cheap to test once).

## 4. Session token flaws beyond JWT

- Tokens that never expire (reuse after "logout"), tokens not invalidated
  on password change.
- Cookie flags: missing HttpOnly/Secure/SameSite on session cookies.
- Predictable tokens: register two accounts, diff tokens for patterns.

## 5. Validation bar

- Evidence: the ORIGINAL decoded token, the FORGED token, and the
  server accepting the forgery (whoami/admin endpoint response with the
  elevated identity).
- "alg none accepted but no endpoint to abuse" is still a finding
  (medium+): forging works, impact needs an endpoint.
- Always redact nothing needed — keep the token in evidence; it is
  lab-scoped and expires.
