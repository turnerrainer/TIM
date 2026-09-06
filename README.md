# TIM

Token Identity Manager — Rust reimplementation of
[buerokratt/TIM](https://github.com/buerokratt/TIM). Custom JWT lifecycle
(generate / validate / extend / revoke / list) + OAuth2/OIDC
multi-provider authentication + RFC 7662 token introspection, backed
by PostgreSQL.

**Version:** 0.3.0-alpha · **License:** Apache-2.0
· **Docs:** [turnerrainer.github.io/TIM](https://turnerrainer.github.io/TIM/)
· **Images:** `docker.io/turnerrainer/tim:alpha`, `ghcr.io/turnerrainer/tim:alpha`

## Upgrading from 0.2.x

**Breaking:** OIDC discovery is fail-closed on plain HTTP by default
in 0.3.0-alpha. Any provider whose `discovery_url` uses `http://`,
or whose discovery document returns HTTP endpoints, will now refuse
to start / login. Find affected configs before upgrading:

```bash
grep -rnE 'discovery_url:\s*http://' path/to/config/
```

Intentional dev-against-mock setups: set
`oauth2.providers.<id>.allow_http_discovery: true`. Otherwise use
`https://`. Two soft behaviour changes and the full upgrade note
live in [`CHANGELOG.md`](./CHANGELOG.md) under the 0.3.0-alpha
"Upgrading from 0.2.x" section.

## One-command demo

Multi-arch image (linux/amd64 + linux/arm64) on Docker Hub and GHCR.
The image ships with `tim.yaml` and migrations baked in — it needs
a Postgres and an RSA private key mounted, and it runs.

```bash
docker compose up -d
curl http://localhost:8085/health
```

`docker compose up -d` brings Postgres + TIM up together and mounts a
generated RSA key. Generate a custom JWT:

```bash
curl -sX POST http://localhost:8085/jwt/custom/generate \
  -H 'content-type: application/json' \
  -d '{"JWTName":"demo","content":{"sub":"user-123"},"expirationInMinutes":60}'
```

Every published digest is signed keyless via cosign — verify with the
recipe in [book/src/getting-started.md](book/src/getting-started.md).

## Build from source

```bash
git clone -b dev https://github.com/turnerrainer/TIM.git
cd tim
docker compose up -d --build
```

## What TIM does

- **Custom JWT lifecycle** — RS256-signed tokens with custom claims,
  chained extensions (audit trail preserved via `original_jwt_uuid`),
  denylist-based revocation, per-subject paginated listing.
- **OAuth2 / OIDC** — multi-provider authorization code flow
  (Google, TARA, Azure AD, Okta, Auth0 or any OIDC provider); OIDC
  discovery + JWKS caching; state + nonce validation.
- **RFC 7662 introspection** — `POST /introspect` accepts custom
  JWT tokens and returns the standard active/exp/iat/sub/aud/iss/jti
  fields plus custom claims.
- **JWKS** — `GET /jwt/keys/public` publishes the RSA public key so
  downstream services can validate tokens offline.

## What TIM does NOT do

- Password authentication (no local user database).
- Rate limiting (deploy behind an ingress that provides it).
- Admin HTTP endpoints (per DEV-REQUIREMENTS §5.3 — admin surfaces
  stay at the infra layer).
- Secret management (mount the private key and database URL from
  your secret store).

## Documentation

- **Book** — [turnerrainer.github.io/TIM](https://turnerrainer.github.io/TIM/)
  (getting started, config, OAuth2, failure modes)
- **Standards** — [`STANDARDS.md`](./STANDARDS.md) — project-specific
  addendum to Buerostack Rust standards
- **Changelog** — [`CHANGELOG.md`](./CHANGELOG.md)
- **Original JVM TIM** — <https://github.com/buerokratt/TIM>

## Origin

Originally developed at the Information System Authority of Estonia
(Riigi Infosüsteemi Amet, RIA) as the TARA Integration Module. The
Java implementation was later extended by
[Rainer Türner](https://www.linkedin.com/in/rainer-t%C3%BCrner-058b80b8/)
into a universal, provider-agnostic identity manager. This repository
is a from-scratch Rust rewrite of that Java codebase — same feature
surface, same public API, hardened supply chain and container
posture per the Buerostack Rust standards (see
[`../DEV-REQUIREMENTS.md`](../DEV-REQUIREMENTS.md)).
