# 07 — `token_validation` provider sub-config is dead code

**Severity:** MEDIUM (misleading config surface)
**Area:** Config / OAuth2
**Files:**

- `src/config/mod.rs:96-111` (definition + defaults)
- `src/config/mod.rs:82-94` (embedded in `ProviderConfig`)
- `tim.yaml:71-73` (documented in example)

## What happens

`ProviderConfig` includes:

```rust
#[serde(default)]
pub token_validation: TokenValidationConfig,
```

with fields `clock_skew_seconds` (default 60) and `cache_ttl_seconds`
(default 3600). Both are documented in `tim.yaml`. Neither is ever
read anywhere in the codebase — grep for `token_validation`,
`clock_skew`, `cache_ttl` returns only the config definitions:

```
$ grep -rn 'token_validation\|clock_skew\|cache_ttl' src/
src/config/mod.rs: (definitions only)
```

The struct is deserialized but the values are inert.

## Reference — Buerostack Java TIM

`JwtValidationService.validateIdToken` at
`.../oauth2/service/JwtValidationService.java:99-110` uses
`providerConfig.getTokenValidation().getClockSkewSeconds()` for the
`iat` future-date check. The Rust rewrite skipped both ID-token
validation entirely (finding 01) and the tunable that would parametrize
it.

## Impact

- Operators who set `token_validation.clock_skew_seconds: 300` in
  `tim.yaml` believe they've relaxed the check. No check exists.
- The example in `tim.yaml:71-73` is a lie to the operator.
