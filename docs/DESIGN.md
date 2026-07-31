# TIM — Domain Design

Source of truth for what TIM must implement. Distilled from
the Java TIM 2.0 codebase (Spring Boot 3.3.3, Java 17, 4 Maven
modules, ~50 source files). Every endpoint, DB table, config field,
and lifecycle rule below has a direct equivalent in the JVM
implementation and MUST be preserved in the Rust rewrite.

## 1. Mission

TIM is a **token identity manager**. It owns three concerns:

1. **Custom JWT lifecycle** — the API service issues RS256-signed
   tokens for downstream consumers, tracks them (audit trail),
   supports extension (issue a fresh token that preserves claims),
   supports revocation (denylist), and lists a caller's own tokens.
2. **OAuth2 / OIDC authentication** — proxies the authorization
   code flow to external identity providers (Google, TARA, Azure,
   Okta, Auth0, or any OIDC-compliant provider), validates the ID
   token, and establishes a session.
3. **RFC 7662 introspection** — a single endpoint that answers "is
   this token active, and what does it claim?" — with a dispatcher
   that routes by token type (custom_jwt today, oauth2 planned).

TIM does **not** own passwords, authorization decisions ("can Alice
call X?"), or any admin surface. Those are separate systems.

## 2. Module layout (Rust)

Mirrors the Java module split (common / custom-jwt / oauth2-oidc /
server) reorganized per DEV-REQUIREMENTS §2 (per-capability, not
per-layer):

```
src/
├── main.rs             # tokio entrypoint; config → DB pool → JWT signer
│                       # → OAuth2 registry → router → axum server
├── lib.rs              # public re-exports for integration tests
├── config/mod.rs       # tim.yaml deserialization + env resolution
├── error.rs            # TimError enum + axum IntoResponse
├── db/                 # sqlx pool, migrations runner
├── crypto/             # RSA keypair load, JWKS export
├── jwt/                # custom JWT lifecycle (generate/validate/extend/
│                       # revoke/bulk_revoke/list)
├── oauth2/             # multi-provider OIDC (discovery, auth flow,
│                       # session cache, ID-token validation)
├── introspect/         # RFC 7662 dispatcher + token-type validators
└── router/             # axum route mounting + middleware
```

## 3. HTTP API surface

Every endpoint the Java TIM exposes today, preserved in the Rust
rewrite with the same paths, methods, and request/response shapes.

### 3.1 Custom JWT

| Method | Path | Purpose |
|---|---|---|
| POST | `/jwt/custom/generate` | Issue new RS256 JWT with custom claims |
| POST | `/jwt/custom/validate` | Full validation → structured response |
| POST | `/jwt/custom/validate/boolean` | `true`/`false` plain text |
| POST | `/jwt/custom/revoke` | Denylist a single token |
| POST | `/jwt/custom/revoke/bulk` | Denylist up to 100 tokens (207-style body) |
| POST | `/jwt/custom/extend` | Issue new token preserving claims; denylist old |
| POST | `/jwt/custom/list/me` | Paginated caller-token list (Bearer auth) |
| GET | `/jwt/keys/public` | JWK Set advertising signing public key |

Request/response shapes match Java TIM verbatim. See `book/src/failure-modes.md`
for status codes.

### 3.2 OAuth2 / OIDC

| Method | Path | Purpose |
|---|---|---|
| GET | `/auth/providers` | Enumerate configured providers |
| GET | `/auth/providers/{id}` | Provider detail |
| GET | `/auth/login/{id}` | Start authorization code flow |
| GET | `/auth/callback/{id}` | Complete flow; create session |
| GET | `/auth/session/validate` | Session lookup by `session_id` query |
| GET | `/auth/profile` | Extracted user profile |
| POST | `/auth/logout` | Session invalidation |
| GET | `/auth/health` | Provider registry health |

### 3.3 Introspection (RFC 7662)

| Method | Path | Purpose |
|---|---|---|
| POST | `/introspect` (form) | Standard `token=…&token_type_hint=…` |
| POST | `/introspect` (JSON) | Alternate JSON body |
| GET | `/introspect/types` | Enumerate token-type validators |

### 3.4 Framework

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | `{"status":"ok"}` |

Deliberately no `/openapi.json` in the MVP (Java TIM has one via
springdoc). If needed, generated statically from a hand-written spec
under `book/src/reference/` — no runtime dep.

## 4. Database schema (PostgreSQL 16)

Two schemas. Everything is UUID-keyed. `jwt_metadata` rows are
INSERT-only (immutable audit log); revocation goes to `denylist`,
not an UPDATE on `jwt_metadata`.

### 4.1 `custom_jwt` schema

**`custom_jwt.jwt_metadata`** — one row per generated custom JWT.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | Row identity |
| `jwt_uuid` | uuid NOT NULL | The token's `jti` claim |
| `created_at` | timestamptz NOT NULL DEFAULT now() | Row insert time |
| `claim_keys` | text NOT NULL | Comma-separated custom claim names (audit) |
| `issued_at` | timestamptz NOT NULL | JWT `iat` claim |
| `expires_at` | timestamptz NOT NULL | JWT `exp` claim |
| `subject` | text | JWT `sub` claim |
| `jwt_name` | text | Caller-supplied friendly name |
| `audience` | text | JWT `aud` claim (comma-joined if multi) |
| `issuer` | text | JWT `iss` claim (defaults to config) |
| `supersedes` | uuid | `id` of the row this one replaces (extension chain) |
| `original_jwt_uuid` | uuid NOT NULL | First `jti` in chain (== `jwt_uuid` for root) |

Indexes:
- `idx_custom_jwt_metadata_subject (subject)`
- `idx_custom_jwt_metadata_issued (issued_at)`
- `idx_custom_jwt_metadata_jwt_uuid (jwt_uuid, created_at DESC)`
- `idx_custom_jwt_metadata_original (original_jwt_uuid)`

**`custom_jwt.denylist`** — revoked JWT identifiers.

| Column | Type | Notes |
|---|---|---|
| `jwt_uuid` | uuid PK | The token's `jti` |
| `created_at` | timestamptz NOT NULL DEFAULT now() | Row insert time |
| `denylisted_at` | timestamptz NOT NULL DEFAULT now() | Revocation time |
| `expires_at` | timestamptz NOT NULL | For TTL cleanup |
| `reason` | text | Free-form reason string |

Indexes: `idx_custom_jwt_denylist_exp (expires_at)`.

### 4.2 `auth` schema

**`auth.oauth_state`** — CSRF state + PKCE verifier persistence.

| Column | Type | Notes |
|---|---|---|
| `state` | text PK | Random hex string in `?state=` param |
| `created_at` | timestamptz NOT NULL DEFAULT now() | Row insert time |
| `pkce_verifier` | text | PKCE `code_verifier` (nullable for MVP) |
| `provider_id` | text NOT NULL | Which provider this state belongs to |
| `nonce` | text | OIDC nonce for replay protection |
| `redirect_uri` | text | Redirect URI provided by caller |

**`auth.jwt_metadata`** (RFC 7662 introspection cache — planned;
schema mirrors `custom_jwt.jwt_metadata` for future OAuth2 token
metadata).

**`auth.denylist`** (OAuth2 token denylist — planned; mirrors
`custom_jwt.denylist`).

The MVP session store is in-process (see §7); Postgres session
tables are in the backlog (`tasks/backlog/002-oauth2-session-store.md`).

## 5. Configuration surface

Loaded from `tim.yaml` per DEV-REQUIREMENTS §5.2. Search order:
`--config` flag → `TIM_CONFIG` env → `./tim.yaml` → built-in defaults.

Full field reference lives in `book/src/configuration.md`. Passwords
and secrets follow the `<field>_env: NAME` pattern — the config
points at an env var, and startup refuses if that env var is unset
when the referring section is configured.

## 6. Crypto

- **Signing algorithm**: RS256 (RSA PKCS#1 v1.5 with SHA-256). Only.
- **Key source**: PKCS#8 PEM file loaded once at startup from
  `jwt.private_key_path`. Public half derived and exposed via
  `/jwt/keys/public` (JWKS) with the configured `kid`.
- **Rotation**: re-deploy with new key path. No in-process
  rotation endpoint (per DEV-REQUIREMENTS §5.3 — no admin surface
  in-process).
- **JWKS caching**: consumers cache `/jwt/keys/public` with their
  own TTL. Old tokens continue to validate until every consumer's
  cache clears.

The Java TIM uses a JKS keystore + `nimbus-jose-jwt`. The Rust
rewrite uses PKCS#8 PEM + `jsonwebtoken` + `rsa` for parsing.
Rationale: PKCS#8 PEM is toolchain-agnostic (`openssl`, `ssh-keygen`,
cloud KMS exports); JKS ties operators to Java tooling.

## 7. Token lifecycle model

State machine per custom JWT:

- **Active**: signature valid, `exp > now()`, `jti` not in denylist.
- **Expired**: `exp <= now()`. Never expires from `jwt_metadata`
  (audit trail permanent); expired rows are `active = false` on
  introspect.
- **Revoked**: `jti` present in `custom_jwt.denylist`.
- **Extended**: `denylist` row exists (from the extension) AND a
  successor row in `jwt_metadata` links back via `supersedes`.

Extension chain preserves `original_jwt_uuid`. To reconstruct chain:
`SELECT * FROM custom_jwt.jwt_metadata WHERE original_jwt_uuid = ?
ORDER BY created_at ASC`.

Extension preserves original `audience` (extracted from prior JWT
claims), regenerates standard JWT fields (`iss`, `iat`, `exp`,
`jti`), and copies custom claims verbatim.

## 8. OAuth2 / OIDC flow

Standard authorization code flow.

1. Consumer hits `GET /auth/login/{provider_id}?redirect_uri=...`.
   TIM generates `state` + `nonce`, persists to
   `auth.oauth_state`, returns `{authorization_url, state}`.
2. Consumer redirects the user to `authorization_url`.
3. Provider redirects back to
   `GET /auth/callback/{provider_id}?code=...&state=...`.
4. TIM validates `state` (single-use; DELETE from `auth.oauth_state`),
   exchanges `code` → tokens at the provider's token endpoint,
   validates the ID token (signature via cached JWKS, `iss`, `aud`,
   `exp`, `nonce`), creates a session (in-process MVP).
5. Session ID returned to caller; subsequent endpoints look up the
   session by ID.

Provider config:
- Discovery URL (OIDC `.well-known/openid-configuration`).
- Client ID + secret (via env vars).
- Scopes (default `openid profile email`).
- Claim mappings (map provider claim names → canonical fields).
- Token validation knobs (clock skew, JWKS cache TTL).

**Session storage MVP** is in-process `DashMap`. See STANDARDS.md
§Project-specific extras. Backlog task 002 replaces it with Postgres.

## 9. Introspection dispatcher

`POST /introspect` accepts a token and dispatches to the appropriate
validator based on token type detection:

1. If the token parses as a JWT with `iss` matching TIM's configured
   issuer → route to `CustomJwtValidator`.
2. Else if it has a claim `token_type: "custom_jwt"` → same.
3. Otherwise return `{"active": false}` (RFC 7662 §2.2 — do not
   leak whether the token is malformed vs. unknown).

Extensible: register additional validators via
`register_validator(token_type, impl Validator)`.

## 10. Security posture inventory

- **CSRF**: not applicable to any JSON API endpoint (all state-changing
  endpoints require a valid Bearer JWT or accept only tokens as
  input, not session cookies).
- **State parameter**: mandatory on `/auth/login/*` flow (single-use,
  DB-backed).
- **Nonce**: mandatory for ID token validation.
- **PKCE**: schema supports (`pkce_verifier` column); wiring is
  backlog task 003.
- **Request size caps**: `server.max_request_bytes` (default 1MB),
  `jwt.max_claims_bytes` (default 32KB) enforced via `DefaultBodyLimit`.
- **Request timeouts**: `server.request_timeout_seconds` (default 30s)
  enforced via `tower_http::timeout`.
- **XXE**: TIM parses no XML. Not applicable.
- **Recursion depth**: JSON depth capped via `serde_json` default.
- **Admin endpoints**: none. Explicitly per DEV-REQUIREMENTS §5.3.
- **Rate limiting**: not implemented. Deploy behind an ingress that
  provides it.
- **Secret exposure in logs**: none. `tracing` calls never take
  passwords, private key material, or full JWTs — only `jti` +
  subject + status.

## 11. Bugs / gotchas from the Java implementation to NOT repeat

Documented for the Rust rewrite so we don't repeat them:

- **Default password `changeme`** on the JVM keystore is a config
  documented pitfall. Rust: no default password — startup refuses if
  the key is encrypted and no passphrase is provided.
- **In-memory session storage without warning** — Java TIM has this
  same limitation but doesn't call it out. Rust: STANDARDS.md
  §Project-specific extras + runtime WARN log at startup + `tim.yaml`
  comment.
- **`audience` field ambiguity** — Java accepts String or List via
  Jackson magic. Rust: explicit `enum { Single(String), Multi(Vec<String>) }`
  with a custom `Deserialize`.
- **`spring.datasource.password=123`** default. Rust: no default;
  refuse to start if `TIM_DATABASE_URL` (or the env var configured)
  is unset.

## 12. What the Rust rewrite deliberately does NOT do vs Java TIM

- **No OpenAPI runtime generation** — Java TIM uses `springdoc`. Rust
  MVP ships a hand-written spec in the book (`book/src/reference/`).
  If runtime OpenAPI is later needed, add via `utoipa` (out of MVP
  scope).
- **No admin endpoints** — Java TIM has no admin endpoints today;
  the constraint is codified so a well-meaning future change doesn't
  add any. See DEV-REQUIREMENTS §5.3.
- **No liquibase** — `sqlx migrate` runs SQL files in `migrations/`
  at startup. Simpler; no XML.
- **No AOP** — the Java `SchemaIsolationAspect` monitors JWT service
  calls for audit. Rust equivalent = explicit `tracing` spans on the
  same call boundaries. If dedicated audit logging becomes a
  requirement, add via `tracing_subscriber` layer, not per-callsite
  boilerplate.

## 13. Reference — the Java TIM bugs / limitations tracked as tasks

- OAuth2 session storage is in-memory (documented in Java TIM
  README, not fixed there) — Rust MVP inherits this; task 002 fixes.
- PKCE columns exist but flow not wired end-to-end — Rust MVP
  inherits; task 003 completes.
- No metrics endpoint — Rust MVP inherits; task 004 adds Prometheus.
