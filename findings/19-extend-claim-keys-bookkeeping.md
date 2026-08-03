# 19 — `extend` writes different `claim_keys` than `generate` for the same claims

**Severity:** LOW (metadata inconsistency)
**Area:** Custom JWT / audit trail
**Files:**

- `src/jwt/service.rs:89-95` (generate — uses `req.content.keys()`)
- `src/jwt/service.rs:389-394` (extend — uses `old.extra.keys()`)

## What happens

`generate` computes `claim_keys` from the raw request `content`, which
still contains registered claims like `"sub"` before `strip_reserved`
runs. So the audit column for a fresh token includes `"sub"` as one of
the "claim keys."

`extend` computes `claim_keys` from `old.extra`, which is what was
signed *after* `strip_reserved` removed `"sub"` (`RESERVED_CLAIM_NAMES`
at `src/jwt/service.rs:549`). So the audit column for an extended
token *excludes* `"sub"`.

The extended token contains the exact same claims (same `sub`, same
custom claims) but the metadata row's `claim_keys` differs. Audit
queries like "which tokens had a `role` claim" work; queries like
"which tokens had a `sub` claim" become bimodal.

## Reference — Buerostack Java TIM

`CustomJwtService.generate` at `.../CustomJwtService.java:33`:
`String.join(",", claims.keySet())` — same "include everything" logic.

`CustomJwtService.extend` at `.../CustomJwtService.java:122-129`
explicitly `remove()`s `iss`, `aud`, `exp`, `iat`, `jti` (but *not*
`sub`) from `existingClaims`, then uses `existingClaims.keySet()`.
So Java's extend includes `sub` in `claim_keys`, matching generate.

## Impact

- Any analytics or forensic query keyed on `claim_keys LIKE '%sub%'`
  under-counts extended tokens.
- Bug is invisible to end users.

## Root-cause note

This is the "read your fix as a stranger" pattern from CLAUDE.md.
Extend was clearly written by pattern-matching on generate, but the
input to `strip_reserved` was already stripped, so the intermediate
value fed into the audit column is different.
