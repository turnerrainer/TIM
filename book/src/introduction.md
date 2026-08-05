# TIM

Rust re-implementation of the Token Identity Manager. TIM issues,
tracks, and validates JSON Web Tokens; brokers OAuth2 / OIDC
authentication against upstream identity providers; and answers
RFC 7662 introspection requests. Backed by PostgreSQL.

**Version:** 0.2.0-alpha.1 · **License:** Apache-2.0

## One-command demo

Bring up TIM and Postgres:

```bash
docker compose up -d
```

Health check:

```bash
curl http://localhost:8085/health
# {"status":"ok"}
```

Generate a custom JWT (privileged endpoints require an admin token —
see [Security hardening](./security-hardening.md)):

```bash
curl -sX POST http://localhost:8085/jwt/custom/generate \
  -H 'content-type: application/json' \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN" \
  -d '{"JWTName":"demo","content":{"sub":"user-123"},"expirationInMinutes":60}'
```

Response:

```json
{
  "status": "created",
  "jwt_name": "demo",
  "token": "eyJhbGciOi...",
  "expires_at": "2026-07-30T09:12:34Z"
}
```

Validate it (validate is public — no admin token needed):

```bash
curl -sX POST http://localhost:8085/jwt/custom/validate \
  -H 'content-type: application/json' \
  -d '{"token":"eyJhbGciOi..."}'
```

## What TIM does

- **Custom JWT lifecycle** — generate, validate, extend (issue a
  fresh token preserving the old claims), revoke (single or bulk),
  and list a caller's tokens. Every issue is logged to an immutable
  audit table.
- **OAuth2 / OIDC** — proxy the authorization code flow to any
  standard OIDC provider (Google, TARA, Azure AD, Okta, Auth0, or
  any provider that publishes a discovery document). Full ID-token
  validation: JWKS-fetched signature, `iss`, `aud`, `exp`, `nbf`,
  `iat` (with configurable clock skew), and mandatory nonce match.
- **RFC 7662 introspection** — a single endpoint that answers "is
  this token active?" for any TIM-issued custom JWT.
- **Session persistence** — sessions stored either in-process
  (`session_store: "memory"`, default) or in Postgres with
  AEAD-encrypted profile data (`session_store: "postgres"`).
  Multi-replica-safe when Postgres is selected.
- **Legacy Buerokratt-TIM compatibility** — `GET /jwt/userinfo`,
  `POST /jwt/blacklist`, `POST /jwt/custom-jwt-blacklist` still
  present for the Ruuter DSL corpus. See
  [Legacy compatibility](./legacy-compat.md).

## What TIM does NOT do

- Password authentication (no local user database).
- Authorization ("can Alice call X?" — that's the calling service).
- Rate limiting (deploy behind an ingress that provides it).
- Admin HTTP endpoints for TIM itself (an admin *token* gates the
  privileged endpoints, but there is no admin surface for managing
  users, keys, or config at runtime).
- Secret management (mount the private key, database URL, admin
  token, and session encryption key from your secret store).

## Where to next

- [Getting started](./getting-started.md) — install + first token
  in five minutes.
- [Configuration](./configuration.md) — every field of `tim.yaml`
  and every env var TIM understands.
- [OAuth2 / OIDC](./oauth2.md) — provider setup, discovery cache,
  session model, ID-token verification.
- [Security hardening](./security-hardening.md) — admin gate, HTTP
  security headers, CORS, schema-role isolation, key rotation.
- [Legacy compatibility](./legacy-compat.md) — the three cookie-borne
  endpoints kept alive for the Ruuter DSL corpus.
- [Migrating from JVM TIM](./migration-from-jvm.md) — behavioural
  and shape changes vs. Buerokratt / JVM 2.0.
- [Failure modes](./failure-modes.md) — every HTTP status TIM can
  return and its cause.
