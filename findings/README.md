# TIM-on-Rust — Audit findings

Audit performed on 2026-08-04 against:

- **Original TIM (Buerokratt)**: `/home/rainer/Desktop/Buerokratt/GitHub/TIM`
  (Java / Spring Boot; the original Estonian government TIM.)
- **TIM 2.x rewrite (Buerostack)**: `/home/rainer/Desktop/Buerostack/TIM`
  (Java / Spring Boot; multi-provider OIDC rewrite. The immediate
  parent TIM-on-Rust claims parity with — commit `d4c27c3
  feat(001): full Rust rewrite of TIM at parity with JVM 2.0`.)
- **TIM-on-Rust (subject)**: `/home/rainer/Desktop/Buerostack/TIM-on-Rust`
  (Rust / Axum rewrite, version `0.1.0-alpha.1`.)

Each finding is a standalone Markdown file with file:line references
into all three code-bases and a severity grade. No fixes were applied;
this is a survey only.

## Severity ladder

- **CRITICAL** — security-relevant, silent data loss, or spec
  violation that produces wrong answers in production.
- **HIGH** — parity gap that a caller can observe, or a deployment
  posture that materially weakens security.
- **MEDIUM** — correctness bug that is unlikely to trigger but real,
  or an ergonomics / robustness regression vs. the JVM version.
- **LOW** — cosmetic, docs drift, dead code, misleading comment.

## Executive summary

- **The single biggest issue is finding 01**: OAuth2 ID tokens are
  never signature-verified. Any actor who can influence the IdP token
  response can create a TIM session for an arbitrary subject. The
  CHANGELOG.md claims otherwise (finding 28).
- **The hint the user provided ("stores session data in-memory
  instead of a database") is confirmed**: findings 03, 09, 29. The
  `session_store` config knob is a string that is silently ignored;
  only in-memory sessions are supported regardless of setting.
- **Custom-JWT lifecycle has a live-token-bypass**: revoked bearer
  tokens still authenticate `POST /jwt/custom/list/me` (finding 13).
- **Multiple API-response schema changes** vs. JVM 2.0 without any
  CHANGELOG note: pagination semantics (14), `Set-Cookie` dropped
  (15), status-string values (16), JWKS shape (20).
- **Deployment posture regressions**: no schema-level DB isolation
  (23), no CORS/CSP/HSTS (25), `/jwt/custom/generate` publicly
  callable (26), session IDs in URL (27), unusable production
  `redirect_uri` default (30).
- **Docs/tasks drift**: a backlog task references a `SessionStore`
  trait that does not exist (12); CHANGELOG overclaims (28).

## Index (severity → finding)

### CRITICAL

- [01 — OIDC ID token signature is NEVER verified](01-id-token-signature-not-verified.md)

### HIGH

- [02 — ID-token nonce check is optional, not mandatory](02-nonce-check-optional-and-lenient.md)
- [03 — `oauth2.session_store` config key is silently ignored](03-session-store-config-ignored.md)
- [13 — `POST /jwt/custom/list/me` accepts revoked bearer tokens](13-list-me-does-not-check-denylist.md)
- [26 — `POST /jwt/custom/generate` is unauthenticated and unrestricted](26-jwt-generate-has-no-authn.md)

### MEDIUM

- [04 — OAuth2 callback rejects IdP error responses as 400 bad-request](04-callback-error-not-handled.md)
- [05 — `redirect_uri` from client accepted without validation](05-redirect-uri-not-validated.md)
- [06 — OIDC discovery document not validated on fetch](06-discovery-doc-not-validated.md)
- [07 — `token_validation` provider sub-config is dead code](07-token-validation-config-dead-code.md)
- [09 — Session TTL is not capped to the configured maximum](09-session-ttl-not-capped.md)
- [10 — `auth.oauth_state` rows are never garbage-collected](10-oauth-state-orphan-rows.md)
- [11 — `auth.oauth_state` age is not checked at callback](11-state-age-not-checked.md)
- [14 — `POST /jwt/custom/list/me` pagination semantics differ from JVM](14-pagination-semantics-differ.md)
- [15 — `setCookie` request field silently ignored](15-set-cookie-silently-ignored.md)
- [16 — `TokenResponse.status` and revoke/HTTP semantics diverge from JVM](16-status-field-values-differ.md)
- [23 — Schema-level DB permission isolation lost](23-schema-isolation-defense-lost.md)
- [25 — No CORS, CSP, HSTS, or other security-response middleware](25-no-cors-no-csp-no-security-headers.md)
- [27 — Session IDs travel in the URL query string](27-session-id-in-query-string.md)
- [28 — CHANGELOG overclaims OAuth2 capabilities](28-changelog-overclaims-id-token-validation.md)

### LOW

- [08 — OIDC discovery fetch has no retry policy](08-discovery-no-retry.md)
- [12 — Backlog doc references a `SessionStore` trait that does not exist](12-sessionstore-trait-does-not-exist.md)
- [17 — `token_type` claim not injected into signed JWT](17-token-type-claim-not-signed.md)
- [18 — `POST /jwt/custom/extend` default TTL differs](18-extend-default-differs.md)
- [19 — `extend` writes different `claim_keys` than `generate`](19-extend-claim-keys-bookkeeping.md)
- [20 — `GET /jwt/keys/public` response shape differs from JVM](20-jwks-response-shape-differs.md)
- [21 — `POST /introspect` returns full claim set for expired custom JWTs](21-introspection-leaks-claims-on-expired.md)
- [22 — `POST /introspect` returns 415 on missing/unknown Content-Type](22-introspect-form-not-restricted-to-mediatype.md)
- [24 — DB pool tuning is minimal — no acquire timeout, no idle timeout](24-db-pool-tuning-partial.md)
- [29 — `MemoryStore::touch` is never invoked; `last_activity` is frozen](29-session-touch-never-called.md)
- [30 — Default `redirect_uri` is `http://localhost:{server.port}/...`](30-default-redirect-uri-hardcoded-localhost.md)

## Recommended fix order

1. Findings 01, 02 (ID-token verification and nonce) — the OIDC callback
   is currently a subject-forgery endpoint. Everything else is
   secondary.
2. Finding 13 (list/me denylist) — same category, custom-JWT side.
3. Finding 26 (generate authn) — likely a design decision, but the
   docs must at least tell operators to gate this endpoint at the
   proxy.
4. Findings 03 + 09 (session store + TTL cap) together — same
   subsystem, same seam.
5. Findings 10, 11 (oauth_state hygiene) — cheap; same subsystem.
6. Everything else in severity order.

## What was NOT audited

- The `book/` mdBook content.
- `CI/CD workflows` (`.github/workflows`).
- The Rust `Cargo.lock` supply chain (deferred to `cargo audit` /
  `cargo-deny` running in CI).
- Test *quality* (only *coverage vs. Java tests* was compared — Java
  has ~15 unit + integration tests spanning validators and
  repositories; Rust has 9 integration + 5 OAuth2 stubs. The Rust
  callback flow has zero end-to-end coverage against a mock IdP,
  which is why finding 01 slipped past the test suite.).
- Cross-compile and container behaviour on non-x86 architectures.
- Concurrency correctness of `DashMap` under adversarial load
  patterns.
