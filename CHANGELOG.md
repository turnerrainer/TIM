# Changelog

All notable changes to TIM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-alpha.1] - 2026-08-05

Second alpha. Post-audit release: fixes silent-drop bugs from
0.1.0-alpha.1, restores JVM 1.x + JVM 2.0 contract parity where
downstream DSLs depend on it, adds TARA integration coverage, adds
an admin-token gate on state-changing endpoints, and lands a
Postgres session store as an alternative to the default in-memory
one.

**Still alpha.** Two significant features are spec'd but not
implemented:

- **`mint-jwt-from-session`** — no endpoint yet for deriving a
  TIM-signed service JWT from an OAuth2 session. Downstream
  services calling TIM-behind-Ruuter for authorised APIs still
  need to hit `/auth/session/validate` per request or generate
  a fresh JWT via the admin gate.
- **PKCE** — the authorization code flow does not send PKCE
  parameters. Providers that mandate PKCE (some TARA and Google
  client registrations do) will reject the login.

Live-fire testing against real TARA / Google sandboxes has NOT
been done — the TARA integration tests use a mock IdP.

### Test coverage at release

96 tests total, `--test-threads=1`:

| Binary | Count | Purpose |
|---|---|---|
| `cargo test --lib` | 42 | Config validation, crypto primitives, session-store semantics, admin gate, JWKS parsing, ID-token helpers |
| `it_jwt_lifecycle` | 7 | Custom JWT generate → validate → extend → revoke |
| `it_legacy_compat` | 15 | All eight JVM 1.x cookie-borne endpoints end-to-end |
| `it_oauth2` | 6 | Provider registry, session-auth surfaces, health |
| `it_oauth2_callback` | 3 | End-to-end OAuth2 callback with a mock IdP |
| `it_oauth2_tara` | 7 | TARA-specific claim shape + five rejection paths |
| `it_regression_findings` | 11 | Regression tests for behaviours fixed post-audit |

### Fixed — security-relevant

- **OIDC ID-token verification is now performed on every callback.**
  Signature (via the provider's cached JWKS), `iss` (must match
  `discovery.issuer`), `aud` (must contain `client_id`), `exp`,
  `nbf`, `iat` (with configurable clock skew), and mandatory `nonce`
  comparison — all constant-time where relevant. Refuses `alg=none`
  and symmetric algorithms outright. The 0.1.0-alpha.1 callback did
  not verify the ID token at all.
- **Mandatory `nonce` on ID tokens.** A missing `nonce` claim is
  now a hard rejection; the previous behaviour silently accepted
  tokens without a nonce claim.
- **`oauth2.session_store` config value is enforced.** Values other
  than `"memory"` or `"postgres"` fail at startup.
- **Session TTL is capped** at `min(configured_ttl_seconds,
  expires_in-from-IdP)`; oversized `expires_in` no longer
  produces an immortal session.
- **`POST /jwt/custom/list/me` checks the denylist.** Revoked
  bearer tokens can no longer enumerate the caller's other
  tokens until natural expiry.
- **Admin-token gate on state-changing custom-JWT endpoints.**
  `/jwt/custom/generate`, `/revoke`, `/revoke/bulk`, `/extend`
  now require `X-TIM-Admin-Token:` or `Authorization: Bearer <admin>`.
  Configured via `security.admin_token_env`. Startup refuses
  when `require_admin_token: true` (default) and the env var is
  missing.

### Fixed — OAuth2 / OIDC

- **Callback bubbles IdP `error=` responses** as structured 400
  instead of "missing field code" schema-validation errors.
- **`redirect_uri` per-provider allow-list** via
  `oauth2.providers.<id>.allowed_redirect_uris`. Caller-supplied
  URIs must match an entry exactly; falls back to the first
  entry when the caller omits.
- **Discovery documents are validated** for required fields plus
  `grant_types_supported: authorization_code` and
  `response_types_supported: code`.
- **Discovery fetch retries with exponential backoff** on 5xx and
  network errors (three attempts). 4xx fails fast.
- **`token_validation.clock_skew_seconds` / `cache_ttl_seconds`
  are consumed** by the ID-token verifier — previously they were
  parsed but ignored.
- **`auth.oauth_state` rows have an age cap** enforced in the
  `DELETE ... RETURNING` clause. Default 300 s (JVM 2.0 parity).
  A background sweeper reaps stale rows every
  `session_sweep_interval_seconds` (default 60 s).
- **Session ID transport moved to headers** — `Authorization:
  Bearer sess_<id>` or `X-TIM-Session: <id>` are the primary
  transports. Legacy `?session_id=<id>` query still accepted for
  backward compatibility.
- **`server.public_base_url` config field** replaces the hardcoded
  `http://localhost:8085` callback synthesis. Empty means "caller
  must pass `?redirect_uri=` explicitly."
- **`provider.claim_mappings` can now target registered JWT
  claims** (`sub`, `iss`, `aud`). TARA's personal-code mapping
  (`personal_code: "sub"`) works correctly.

### Fixed — Custom JWT lifecycle

- **`POST /jwt/custom/revoke` returns 409** on idempotent repeat;
  matches JVM 2.0's semantics.
- **`POST /jwt/custom/validate` returns 401** on invalid/expired/
  revoked tokens; the body's `valid`/`active`/`reason` fields
  still carry the details. Matches JVM 2.0.
- **`POST /jwt/custom/generate` returns `status: "created"`;
  `POST /jwt/custom/extend` returns `status: "extended"`.**
  Response-shape parity with JVM 2.0.
- **`setCookie: true` in request body actually emits `Set-Cookie`**
  on the response. Attributes: `Path=/; HttpOnly; Secure;
  SameSite=Lax` (adds `Secure` + `SameSite` beyond JVM defaults).
- **`token_type: "custom_jwt"` claim is signed into every custom
  JWT** at generate time; extended tokens preserve or backfill it.
- **`POST /jwt/custom/extend` default TTL is 60 minutes** when the
  caller omits `expirationInMinutes` (JVM 2.0 parity).
- **`POST /jwt/custom/list/me` pagination** accepts JVM `page`
  semantics (`offset` = page number, `limit` = page size, default
  20); response carries both `page`/`size`/`total_pages` and
  `offset`/`limit` (row shape). Opt-in `by_row: true` interprets
  `offset` as row offset.
- **`jwt_name` filter is honoured** on `POST /jwt/custom/list/me`
  (was silently ignored in JVM 2.0).
- **`POST /introspect` returns uniform `{"active": false}`** on
  every inactive path (unknown, revoked, expired, wrong issuer,
  bad signature).
- **`POST /introspect` accepts JSON or form** even without a
  Content-Type header (best-effort parse).

### Added — legacy compatibility endpoints

Restored the eight cookie-borne endpoints the original Buerokratt
TIM exposed and JVM 2.0 dropped. These coexist with the modern
header/body shapes — nothing was replaced.

- `GET /healthz` — alias for `GET /health`.
- `GET /jwt/verification-key` — signing public key as PKCS#1 PEM.
- `GET /jwt/userinfo` — read JWT from configured cookie name.
- `POST /jwt/custom-jwt-verify` — verify JWT from cookie named in body.
- `POST /jwt/custom-jwt-userinfo` — read JWT from cookie named in body.
- `POST /jwt/custom-jwt-extend` — admin-gated; extend + refresh cookie.
- `GET /jwt/extend-jwt-session` — admin-gated; extend default cookie.
- `POST /jwt/custom-jwt-blacklist` — admin-gated; body = cookie name.
- `POST /jwt/blacklist` — admin-gated; three modes (cookie /
  `?jwt=<uuid>` / `?sessionId=<id>`). Returns real status codes
  (200 / 409 / 404) instead of JVM 1.x's "always 200."

Config knob for the cookie name: `jwt.cookie_name` (default `"jwt"`;
set to `"JWTTOKEN"` for JVM 1.x DSL parity).

### Added — TARA (Estonian eID) integration

Config-only integration. Full "TARA" section added to the OAuth2
book chapter covering:

- Provider block for `tara-test.ria.ee` and `tara.ria.ee`.
- Claim mapping: `personal_code: "sub"`, `first_name: "given_name"`,
  `last_name: "family_name"`, `acr`, `amr`, `date_of_birth`.
- Scope semantics (`openid`, `openid phone`, `openid idcard`,
  `openid mid`).
- Test-vs-prod discovery URL swap.
- LoA policy hand-off (target extracts `acr`; downstream services
  enforce policy).

Integration coverage: 7 test cases exercising personal-code
+ Estonian UTF-8 round-trip, `acr`/`amr` array shape,
issuer/kid/`alg=none`/expiry rejection paths, and
`profile_attributes` not being silently promoted.

### Added — HTTP security posture

- **`security.admin_token_env`** — env var name holding the
  privileged-endpoint token. Constant-time comparison.
- **CORS layer** via `security.cors_allowed_origins`.
- **Response-header middleware** — `Content-Security-Policy`,
  `Strict-Transport-Security`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy` — all configurable,
  emitted by default with conservative values.
- **Boot-time diagnostic pass** — `AppConfig::diagnose()` logs
  every parsed config field at INFO with WARN on non-secure or
  operator-attention-required settings. Grep for
  `tim::config::diagnose` in logs.

### Added — Postgres session store

- **`oauth2.session_store: "postgres"`** persists sessions across
  process restart and spans replicas. Profile data (which may
  contain IdP-derived PII) is AEAD-encrypted at rest via
  chacha20poly1305 using a 32-byte key from
  `oauth2.session_encryption_key_env` (default
  `TIM_SESSION_ENCRYPTION_KEY`). Startup refuses if the key env
  var is unset or malformed.
- **Background sweeper** deletes expired sessions + stale
  oauth_state rows every `oauth2.session_sweep_interval_seconds`
  (default 60 s).
- **`SessionStore` trait** with `MemoryStore` and `PostgresStore`
  backends. Selected by config at startup.

### Added — Config / lifecycle knobs

- `server.public_base_url` — externally-reachable URL used to
  synthesise the default OAuth2 callback URL.
- `database.acquire_timeout_seconds` / `idle_timeout_seconds` /
  `max_lifetime_seconds` — pool tuning. `test_before_acquire(true)`
  transparently to PgBouncer bouncing.
- `oauth2.session_ttl_seconds` (24 h default), `state_max_age_seconds`
  (5 min default), `session_sweep_interval_seconds` (60 s default).
- `serde(deny_unknown_fields)` on `AppConfig` and every nested
  struct — a typo in `tim.yaml` now fails at startup rather than
  silently defaulting.

### Known API-shape changes vs. JVM 2.0

Additive or documented; no field removed. Callers unaffected in the
common case:

- **`GET /jwt/keys/public`** returns a bare RFC 7517 JWKS
  (`{"keys":[…]}`), not JVM 2.0's `{"jwk": "<stringified JWKS>"}`
  wrapper. Legacy callers use `GET /jwt/verification-key` for the
  PKCS#1 PEM shape instead.
- **List response** carries both pagination shapes
  (`page`/`size`/`total_pages` AND `offset`/`limit`).
- **`Set-Cookie` attributes** add `Secure` and `SameSite=Lax`
  where JVM 1.x omitted both.

## [0.1.0-alpha.1] - 2026-07-30

First alpha release. Rust rewrite of TIM (Java / Spring Boot 3.3.3),
covering the endpoints enumerated in the design document.

### Known limitations at time of release

- ID-token signature verification NOT implemented — deferred and
  treated as a critical bug by the post-release audit. Fixed in
  0.2.0-alpha.1 above.
- Session store hard-coded to in-memory `DashMap`; the
  `oauth2.session_store` config knob was accepted but ignored.
- No admin gate on `/jwt/custom/generate` or related privileged
  endpoints.

### Added — Custom JWT lifecycle

- `POST /jwt/custom/generate` — generate an RS256-signed JWT with
  a custom claims payload, configurable expiration, and optional
  audience. Persists to `custom_jwt.jwt_metadata` with
  `original_jwt_uuid` set to the new token's `jti` (chain root).
- `POST /jwt/custom/validate` — signature, expiration, denylist,
  optional audience + issuer.
- `POST /jwt/custom/validate/boolean` — same checks, plain-text
  `true` / `false` response.
- `POST /jwt/custom/extend` — issue a fresh token preserving the
  original claims + audience; immediately denylists the old one;
  links the new token via `supersedes` + `original_jwt_uuid`.
- `POST /jwt/custom/revoke` — insert the token's `jti` into
  `custom_jwt.denylist`.
- `POST /jwt/custom/revoke/bulk` — up to 100 tokens per request
  (configurable via `jwt.bulk_revoke_max`); returns 207-style body
  with per-token results.
- `POST /jwt/custom/list/me` — paginated list of the caller's
  tokens (bearer JWT in `Authorization`).
- `GET /jwt/keys/public` — JWK Set advertising the signing public
  key.

### Added — OAuth2 / OIDC (MVP)

- `GET /auth/providers`, `GET /auth/providers/{provider_id}`.
- `GET /auth/login/{provider_id}` — authorization code flow init.
- `GET /auth/callback/{provider_id}` — token exchange + session
  creation. **See "Known limitations" above — this path did not
  validate the ID token in this release.**
- `GET /auth/session/validate?session_id=...`,
  `GET /auth/profile?session_id=...`,
  `POST /auth/logout?session_id=...`,
  `GET /auth/health`.
- OIDC discovery + JWKS cached per-provider (`moka`, TTL from
  config).
- Config-driven provider list.

### Added — RFC 7662 introspection

- `POST /introspect` (form + JSON), `GET /introspect/types`.

### Added — Framework

- Config loading (CLI → env → `./tim.yaml` → defaults). Secrets via
  `<field>_env: NAME` pattern.
- `TimError` enum with per-variant HTTP status mapping.
- Postgres pool via `sqlx`. Migrations auto-applied when
  `database.auto_migrate: true`.
- RSA private key loaded once at startup (PKCS#8 PEM).
- Request body size cap, per-request timeout.
- Structured tracing via `tracing_subscriber::EnvFilter`.

### Added — Repository, CI, docs

- `.github/workflows/`: tests, security, publish, docs.
- `book/` mdBook.
- Hardened container: multi-stage build, non-root user, tini init.
- Hardened compose: `read_only`, `cap_drop: ALL`,
  `no-new-privileges`, tmpfs `/tmp`, resource limits, healthcheck.
- `deny.toml` + `.cargo/audit.toml`.

[Unreleased]: https://github.com/turnerrainer/TIM/compare/v0.2.0-alpha.1...HEAD
[0.2.0-alpha.1]: https://github.com/turnerrainer/TIM/compare/v0.1.0-alpha.1...v0.2.0-alpha.1
[0.1.0-alpha.1]: https://github.com/turnerrainer/TIM/releases/tag/v0.1.0-alpha.1
