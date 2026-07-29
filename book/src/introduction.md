# TIM-on-Rust

Rust re-implementation of the Token Identity Manager. TIM issues,
tracks, and validates JSON Web Tokens; brokers OAuth2 / OIDC
authentication against upstream identity providers; and answers
RFC 7662 introspection requests. Backed by PostgreSQL.

**Version:** 0.1.0-rc.1 · **License:** Apache-2.0

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

Generate a custom JWT:

```bash
curl -sX POST http://localhost:8085/jwt/custom/generate \
  -H 'content-type: application/json' \
  -d '{"JWTName":"demo","content":{"sub":"user-123"},"expirationInMinutes":60}'
```

Response:

```json
{
  "status": "ok",
  "jwt_name": "demo",
  "token": "eyJhbGciOi...",
  "expires_at": "2026-07-30T09:12:34Z"
}
```

Validate it:

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
  any provider that publishes a discovery document). Validate the
  returned ID token. Establish a session.
- **RFC 7662 introspection** — a single endpoint that answers "is
  this token active?" for any TIM-issued custom JWT. Extension
  point registered for external-provider tokens (see
  [task 005](https://github.com/turnerrainer/TIM/blob/dev/tasks/backlog/005-jwks-external-token-validation.md)).

## What TIM does NOT do

- Password authentication (no local user database).
- Authorization ("can Alice call X?" — that's the calling service).
- Rate limiting (deploy behind an ingress that provides it).
- Admin HTTP endpoints (per the Buerostack Rust ruleset — admin
  surfaces stay at the infrastructure layer).
- Secret management (mount the private key + database URL from
  your secret store).

## Where to next

- [Getting started](./getting-started.md) — install + first token
  in five minutes.
- [Configuration](./configuration.md) — every field of `tim.yaml`
  and every env var TIM understands.
- [OAuth2 / OIDC](./oauth2.md) — provider setup, discovery cache,
  session model.
- [Failure modes](./failure-modes.md) — every HTTP status TIM can
  return and its cause.
