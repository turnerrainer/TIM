# Changelog

All notable changes to TIM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-07-30

First alpha release. Full Rust rewrite of TIM (Java / Spring
Boot 3.3.3) targeting feature parity with the upstream JVM
implementation, hardened per DEV-REQUIREMENTS.md.

### Added — Custom JWT lifecycle

- `POST /jwt/custom/generate` — generate an RS256-signed JWT with
  a custom claims payload, configurable expiration, and optional
  audience. Persists to `custom_jwt.jwt_metadata` with
  `original_jwt_uuid` set to the new token's `jti` (chain root).
- `POST /jwt/custom/validate` — full validation: signature,
  expiration, denylist, optional audience + issuer. Returns
  structured JSON with `valid`, `active`, `subject`, `expires_at`,
  claim map.
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

- `GET /auth/providers` — list configured providers.
- `GET /auth/providers/{provider_id}` — provider detail.
- `GET /auth/login/{provider_id}` — authorization code flow init;
  returns the provider's `authorization_url` + generated `state`.
- `GET /auth/callback/{provider_id}` — exchange `code` → tokens,
  validate ID token, create session.
- `GET /auth/session/validate?session_id=...` — session lookup.
- `GET /auth/profile?session_id=...` — extracted user profile.
- `POST /auth/logout?session_id=...` — session invalidation.
- `GET /auth/health` — provider registry health.
- OIDC discovery + JWKS cached per-provider (`moka`, TTL from
  config).
- Config-driven provider list — add a standard OIDC provider by
  editing `tim.yaml`, no code changes.
- Session storage MVP: in-process `DashMap`. Postgres-backed
  session store is tracked as `tasks/backlog/002-oauth2-mvp.md`
  follow-up (see also STANDARDS.md §Project-specific extras).

### Added — RFC 7662 introspection

- `POST /introspect` (form + JSON) — standard introspection
  response shape (`active`, `exp`, `iat`, `sub`, `aud`, `iss`,
  `jti`, `token_type`, `extra_claims`).
- `GET /introspect/types` — enumerate token type validators.

### Added — Framework

- Config loading: CLI flag → env var → `./tim.yaml` → built-in
  defaults, per DEV-REQUIREMENTS §5.2. Passwords via
  `<field>_env: NAME` pattern; startup refuses if the referenced
  env var is unset.
- Structured errors: `TimError` enum with per-variant HTTP status
  mapping via `axum::response::IntoResponse`.
- Postgres pool via `sqlx` (async, connection-pooled). Migrations
  auto-applied at startup when `database.auto_migrate: true`.
- RSA private key loaded once at startup (PKCS#8 PEM). Public half
  derived + exposed via JWKS. Rotation = re-deploy.
- Request body size cap via `DefaultBodyLimit`
  (`jwt.max_claims_bytes` on the generate path, global
  `server.max_request_bytes` elsewhere).
- Per-request timeout via `tower_http::timeout`.
- Tracing via `tracing` + `tracing_subscriber::EnvFilter`; `RUST_LOG`
  env var picks the level.

### Added — Repository, CI, docs

- Full `.github/workflows/` set: `tests.yml` (matrix
  `ubuntu-latest` + `ubuntu-24.04-arm`), `security.yml`
  (`cargo audit --deny warnings` + `cargo-deny check all` + daily
  cron), `publish.yml` (multi-arch Buildx, Trivy gate, cosign
  keyless), `docs.yml` (mdBook 0.4.40 + mdbook-linkcheck 0.7.7,
  syncs `CHANGELOG.md` → `book/src/reference/changelog.md`).
- `book/` mdBook: introduction, getting-started, configuration,
  oauth2, failure-modes, reference/changelog.
- Hardened container: multi-stage build (rust:1.88-slim →
  debian:bookworm-slim), non-root user, tini init.
- Hardened compose: `read_only`, `cap_drop: ALL`,
  `no-new-privileges`, tmpfs `/tmp`, resource limits, healthcheck.
- `deny.toml` + `.cargo/audit.toml` mirrored (zero exceptions at
  this release).

[Unreleased]: https://github.com/turnerrainer/tim/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/turnerrainer/tim/releases/tag/v0.1.0-alpha.1
