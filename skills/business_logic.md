---
name: business_logic
description: Business-logic flaws — negative prices, race conditions, workflow bypass, privilege creep
---

# Business Logic Testing (CWE-840, CWE-362)

No scanner finds these; only understanding the intended workflow does.

## 1. Learn the intended flows first

Walk each money/privilege workflow end-to-end as a normal user: register →
browse → basket → checkout → order → review → refund/feedback; plus
role changes (user → admin paths), coupon/points, password reset. Write
down the state machine: what transitions are allowed, what amounts/prices
are server-trusted.

## 2. Parameter trust probes (client-controlled values)

Replay key requests with values the client should never control:

```bash
# Price/quantity manipulation:
curl -s -X PUT <target>/api/basket/7 -d '{"productId":1,"quantity":-1}'
curl -s -X PUT <target>/api/basket/7 -d '{"productId":1,"quantity":0.5}'
curl -s -X POST <target>/api/checkout -d '{"total":0}'          # if total is client-sent
# Integer overflow on quantity: 999999999999, 2**31, 2**53
# Currency/units confusion: price in cents sent as dollars
```

Signals: negative totals, zero-cost orders, refunds larger than payments,
points/coupons applied twice.

## 3. Workflow sequence bypass

- Skip steps: call step N+3 directly with a guessed payload (checkout
  without basket, refund without order, review without purchase).
- Replay: repeat a one-shot action (coupon use, vote, transfer, welcome
  bonus) — session/token reuse.
- Race conditions (gentle, lab-only): fire the same request concurrently
  and count accepted effects:
  ```bash
  printf '%s' '{"coupon":"WELCOME"}' > /tmp/c.json
  for i in 1 2 3 4 5; do
    curl -s -X POST <target>/api/basket/coupon -H 'Content-Type: application/json' \
      -d @/tmp/c.json &
  done; wait
  curl -s <target>/api/basket | jq '.couponDiscountApplied'  # >1 = race
  ```
  Max 5-10 concurrent — this is a logic check, NOT a load test.

## 4. Privilege and data creep

- Role fields client-settable? (`{"role":"admin"}` in profile update.)
- ID + action combos: cancel/modify ANOTHER user's order (ties to idor —
  report the access-control aspect there, the logic aspect here, only if
  distinct).
- Tamper with your own tokens' numeric claims (see auth_jwt specialist's
  turf — don't duplicate).

## 5. Validation bar

- Evidence: the full sequence — intended flow (one request), the mutated
  request, and the server's acceptance proving economic/privilege impact
  (order confirmation with total 0, double-applied coupon, second refund).
- PoC: exact replayable requests in order.
- Severity by money/privilege at stake: free-goods/race on payments =
  high/critical; off-by-one coupon = medium/low.
- "Weird but harmless" responses are not findings — note in the summary.
