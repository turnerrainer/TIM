# 13 — `POST /jwt/custom/list/me` accepts revoked bearer tokens

**Severity:** HIGH (security)
**Area:** Custom JWT
**File:** `src/router/mod.rs:139-157` (`jwt_list_me`)

## What happens

The handler validates the bearer token via a raw
`s.signer.verify(...)` call with only `validate_exp = true`:

```rust
let mut v = Validation::new(Algorithm::RS256);
v.validate_exp = true;
v.validate_aud = false;
v.required_spec_claims.clear();
let decoded = s.signer.verify::<StandardClaims>(&token, &v)...;
let sub = decoded.claims.sub.ok_or(TimError::Unauthorized)?;
```

There is no denylist check. A token that has been revoked but is not
yet past `exp` still authenticates the caller for `list/me`, so the
attacker keeps read access to their token inventory until natural
expiry.

## Reference — Buerostack Java TIM

`CustomJwtController.listMyTokens` at
`.../custom-jwt/.../api/CustomJwtController.java:328-335`:

```java
JwtValidationResponse validation = customJwtService.validate(token, null, null);
if (!validation.isValid() || !validation.isActive()) {
    return ResponseEntity.status(401).body(...);
}
```

`customJwtService.validate` at `.../service/CustomJwtService.java:262-264`
calls `isRevoked(token)` which hits the denylist. Rust skipped this
step and duplicated the decode logic in the handler instead of
delegating to the same code path.

## Impact

- A revoked bearer token remains usable for `list/me` until its
  natural expiry. If the revocation was triggered by
  compromise-detection (e.g., "we think this token leaked"), the
  attacker retains the ability to enumerate the victim's other
  tokens until `exp` passes.
- Confirms the audit-cycle-lessons pattern: two similar-looking
  code paths (`validate` and `list/me` both need "is this token
  live?") drifted apart because the seam wasn't traced.

## Suggested direction

Route bearer-token gating through `JwtService::validate` (or a
dedicated bearer helper) so the denylist check happens exactly once
and every future bearer endpoint inherits it automatically.
