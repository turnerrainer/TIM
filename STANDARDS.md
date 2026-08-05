# STANDARDS

TIM follows every rule in
[`../DEV-REQUIREMENTS.md`](../DEV-REQUIREMENTS.md) — the authoritative
Buerostack Rust ruleset, compiled from Ruuter-on-Rust and XTR
experience. Read that file front-to-back before touching this repo.

This file lists the small set of project-specific extras and
codifies where TIM deviates (with justification) from the
generic ruleset.

## Project-specific extras

### 1. Database is Postgres — real, not mocked

Per DEV-REQUIREMENTS §3, integration tests must not mock the
database. TIM integration tests connect to a real Postgres
instance. Locally this is `docker compose up postgres`; in CI it is
a service container (see `.github/workflows/tests.yml`).

### 2. RSA private key is loaded once, at startup

The JWT signing key is loaded from a PKCS#8 PEM file at startup and
never re-read. To rotate:

1. Deploy a new instance with the new key path.
2. Verify JWKS at `/jwt/keys/public` shows the new `kid`.
3. Drain traffic from the old instance.

The old key's `kid` will disappear from JWKS. Downstream services
that cache JWKS with a TTL keep validating tokens signed with the
old key until the TTL expires.

### 3. Session storage — memory or Postgres

`oauth2.session_store: "memory"` (single-replica, no persistence
across restart) or `"postgres"` (multi-replica, persisted, tokens
AEAD-encrypted at rest via `oauth2.session_encryption_key_env`).
The config value is *enforced* — anything else fails startup. See
`book/src/oauth2.md` for the trade-off.

### 4. ID-token validation is mandatory

Every OAuth2 callback runs the ID token through
`oauth2::idtoken::verify`: JWKS-fetched signature, `iss` /
`aud` / `exp` / `nbf` / `iat` (with configurable clock skew), and
mandatory nonce match. Token responses without an ID token are
rejected. No path skips this.

### 5. Privileged endpoints require an admin token

`/jwt/custom/generate`, `/revoke`, `/revoke/bulk`, `/extend` all
require `X-TIM-Admin-Token` or `Authorization: Bearer` matching
`security.admin_token_env`. Startup refuses when
`security.require_admin_token = true` and the env var is missing.

### 6. Sessions and oauth_state rows are swept

A background task deletes expired sessions + stale `auth.oauth_state`
rows every `oauth2.session_sweep_interval_seconds` (default 60 s).
Set to 0 in tests.

## Deviations from DEV-REQUIREMENTS

None currently.

## Verification set

Every one of these MUST exit 0 before a release. Run under
`--test-threads=1` because the integration tests share Postgres
tables.

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo test --no-fail-fast
cargo audit --deny warnings
cargo deny check all
( cd book && mdbook build )
docker build .
```
