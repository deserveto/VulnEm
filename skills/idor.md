---
name: idor
description: Insecure Direct Object Reference testing — swap IDs, compare responses, prove cross-user access
---

# Insecure Direct Object References / Forced Browsing (CWE-639, CWE-284)

## 1. Set up two test identities

IDOR needs two accounts to prove cross-user access. Register/locate two
users (e.g. `tester@local.test` and `victim@local.test`). Note their ids,
tokens, and one private resource each (order, address, profile, basket).

## 2. Map object references

From the endpoint map, list every request carrying an identifier:
`/api/users/7`, `/api/baskets/3`, `/rest/order/42`, `?uid=`, JSON body ids,
UUIDs in responses. Sequential ints are the classic case; UUIDs are weaker
but still testable (leak via listing endpoints).

## 3. Swap and compare — the core probe

```bash
# As tester (authenticated), fetch VICTIM's object:
curl -s -H "Authorization: Bearer $TESTER_TOKEN" <target>/api/users/<victim_id> -o /tmp/victim.json
# Baseline: fetch your own object for comparison
curl -s -H "Authorization: Bearer $TESTER_TOKEN" <target>/api/users/<tester_id> -o /tmp/self.json
diff /tmp/self.json /tmp/victim.json; head -c 400 /tmp/victim.json
```

Also test the unauthenticated variant (drop the token entirely), and
HTTP-verb variants (`PUT`/`DELETE` on the other user's object — write-IDOR
is higher severity than read-IDOR).

## 4. Hunt hidden references

```bash
# Listing endpoints often leak other users' ids/UUIDs:
curl -s <target>/api/users | jq '.[0:3]'
# Admin or internal numbering (orders, receipts, tracking codes):
curl -s -o /dev/null -w '%{http_code}\n' <target>/api/orders/1..5  # loop in bash
```

## 5. Validation bar for report_finding

- Evidence: the swapped-id request WITH auth headers redacted appropriately
  plus the response body proving access to another user's data (email,
  address, order). Include the baseline diff where relevant.
- PoC: exact curl with the tester token, victim id.
- "403 vs 200 difference between ids" alone is weak — show the DATA.
- Severity guide: read-IDOR on private data = high; write/delete IDOR or
  admin-object access = critical/high; public data = info/low.
