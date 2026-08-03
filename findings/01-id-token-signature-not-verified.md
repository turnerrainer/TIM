# 01 — OIDC ID token signature is NEVER verified

**Severity:** CRITICAL (security)
**Area:** OAuth2 / OIDC
**Files:**

- `src/oauth2/flow.rs:205-241` (`extract_profile`)
- Comment at `src/oauth2/flow.rs:170-175` and module doc at
  `src/oauth2/mod.rs:1-6` acknowledge the gap.

## What happens

In `complete_callback` the Rust rewrite takes the `id_token` returned by
the IdP's token endpoint, splits it on `.`, base64-decodes the middle
segment, and treats every claim as trusted. There is:

- **no signature check** against the discovery `jwks_uri`,
- **no `iss` check** against `discovery.issuer`,
- **no `aud` check** against `provider.client_id`,
- **no `exp` / `nbf` / `iat` check**,
- **no `alg=none` guard**.

The only check performed is a nonce comparison, and even that is
short-circuited (see finding 02).

## Reference — Buerostack Java TIM

`app/oauth2-oidc/.../service/JwtValidationService.java:51-131`
performs a full nimbus-JOSE validation:

1. Parse `SignedJWT`.
2. Fetch JWKS via cached `WebClient`, resolve key by `kid`.
3. `RSASSAVerifier` — reject on signature mismatch.
4. `iss` equality against `discovery.getIssuer()`.
5. `aud` contains `providerConfig.getClientId()`.
6. `exp` > now.
7. `nbf` <= now if present.
8. `iat` within `clock_skew_seconds` (default 60) — future dates
   rejected.
9. `nonce` equality if provided.

The Rust version implements only step 9 (partially — see finding 02).

## Impact

Any party that can present *any* JSON blob to the callback (e.g., by
forging a token endpoint response through DNS poisoning, MITM against a
non-HTTPS-pinned upstream, a compromised OIDC provider, a mis-configured
provider that echoes attacker-controlled input, or by simply passing a
crafted `code` value that the token endpoint reflects) can create a TIM
session for **any subject they choose** — including administrative
subjects — because `user_id` is read from the unverified `sub` claim at
`flow.rs:235-239`. Downstream services trusting `auth_profile` /
`auth_session_validate` will believe the impersonated identity.

`tim.yaml:71-73` documents a `token_validation.clock_skew_seconds` /
`cache_ttl_seconds` block that is **never consulted** in code — the
`TokenValidationConfig` struct is deserialized (see
`src/config/mod.rs:96-111`) but never read.

## Suggested fix (out of scope for this audit)

Route ID tokens through a real verifier that consults the discovery
`jwks_uri`, caches keys with the configured TTL, and enforces
`iss` / `aud` / `exp` / `nbf` / `iat` / `nonce` per OIDC Core §3.1.3.7.
The `jsonwebtoken` crate + `moka` is enough; task 005 in
`tasks/backlog/` reportedly tracks this — verify it exists.
