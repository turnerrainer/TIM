# Getting started

Ten-minute install from an empty machine to first JWT.

## 1. Prerequisites

- Docker 20+ with Docker Compose v2 (`docker compose ...`).
- `curl` and `jq`.
- `openssl` (only for generating a demo signing key + admin token —
  you already have this on every modern *nix).

Nothing else. TIM's runtime is a self-contained container image.

## 2. Get the source (only for local build)

If you just want the published image, skip to step 3.

```bash
git clone https://github.com/turnerrainer/TIM.git
cd TIM
```

## 3. Generate a demo RSA signing key

TIM signs JWTs with RS256. Generate a PKCS#8 PEM keypair — the
private half is what TIM loads; the public half is derived and
published automatically at `/jwt/keys/public`.

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out keys/jwt-private.pem
chmod 644 keys/jwt-private.pem
```

Never commit this file. It is a secret. `.gitignore` already
excludes `*.pem` outside `tests/fixtures/`.

## 4. Set the required secrets

TIM refuses to start unless the DB URL and admin token are set.

```bash
export TIM_DATABASE_PASSWORD=demo-only-do-not-use-in-prod
export TIM_ADMIN_TOKEN=$(openssl rand -hex 32)
echo "Save this admin token; you need it for privileged endpoints:"
echo "$TIM_ADMIN_TOKEN"
```

The admin token gates the four privileged endpoints
(`/jwt/custom/generate`, `/revoke`, `/revoke/bulk`, `/extend`, plus
the legacy `/jwt/blacklist` and `/jwt/custom-jwt-blacklist`). See
[Security hardening](./security-hardening.md#admin-token) for how to
provision it in production.

Optional — if you also want persistent OAuth2 sessions across
restarts:

```bash
export TIM_SESSION_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

And in `tim.yaml`:

```yaml
oauth2:
  session_store: "postgres"
```

## 5. Bring TIM + Postgres up

```bash
docker compose up -d
```

Docker Compose starts:

- **`tim-postgres`** — PostgreSQL 16, port 5432 on host.
- **`tim`** — TIM API server, port 8085 on host.

TIM waits for Postgres to be healthy, runs SQL migrations on first
boot, and starts serving.

## 6. Verify the install

Health check:

```bash
curl -sf http://localhost:8085/health
# {"status":"ok"}
```

Check that security response headers are set:

```bash
curl -sI http://localhost:8085/health | grep -Ei 'content-security|strict-transport|x-frame|x-content-type|referrer'
# content-security-policy: default-src 'none'; frame-ancestors 'none'
# strict-transport-security: max-age=63072000; includeSubDomains
# referrer-policy: no-referrer
# x-frame-options: DENY
# x-content-type-options: nosniff
```

Public JWKS (proves the key loaded and TIM is signing-ready):

```bash
curl -s http://localhost:8085/jwt/keys/public | jq
# {
#   "keys": [
#     {"kty":"RSA","alg":"RS256","use":"sig","kid":"tim-rs-1","n":"...","e":"AQAB"}
#   ]
# }
```

## 7. Generate your first JWT

```bash
TOKEN=$(curl -sX POST http://localhost:8085/jwt/custom/generate \
  -H 'content-type: application/json' \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN" \
  -d '{"JWTName":"welcome","content":{"sub":"you"},"expirationInMinutes":15}' \
  | jq -r .token)
echo "$TOKEN"
```

Try the same request without the admin header — you get 401:

```bash
curl -sX POST http://localhost:8085/jwt/custom/generate \
  -H 'content-type: application/json' \
  -d '{"JWTName":"nope","content":{"sub":"you"},"expirationInMinutes":15}' \
  -o /dev/null -w 'HTTP=%{http_code}\n'
# HTTP=401
```

Decode the payload (no admin token needed to read a JWT — anyone
holding it can decode):

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

Validate (public):

```bash
curl -sX POST http://localhost:8085/jwt/custom/validate \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$TOKEN\"}" | jq
```

Response includes `valid: true`, `active: true`, the subject, and
the full claim map. HTTP status is 200 when active, 401 when not.

## 8. Introspect (RFC 7662)

```bash
curl -sX POST http://localhost:8085/introspect \
  -d "token=$TOKEN" | jq
```

## 9. Revoke (admin-gated)

```bash
curl -sX POST http://localhost:8085/jwt/custom/revoke \
  -H 'content-type: application/json' \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN" \
  -d "{\"token\":\"$TOKEN\",\"reason\":\"demo cleanup\"}" | jq
# {"status":"revoked","message":"Token has been successfully revoked"}
```

Second call returns 409 (idempotent):

```bash
curl -sX POST http://localhost:8085/jwt/custom/revoke \
  -H 'content-type: application/json' \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN" \
  -d "{\"token\":\"$TOKEN\"}" \
  -o /dev/null -w 'HTTP=%{http_code}\n'
# HTTP=409
```

Re-validate — HTTP 401, body `reason: "revoked"`.

## 10. Legacy cookie-borne endpoints

If you are migrating existing Ruuter DSL flows that expect
`GET /jwt/userinfo`, `POST /jwt/blacklist`, or
`POST /jwt/custom-jwt-blacklist`, those endpoints are still present.
See [Legacy compatibility](./legacy-compat.md) for the mapping and
usage.

## 11. Verify the image cosign signature (optional, recommended)

Every published tag is signed keyless via cosign. From a machine
with `cosign` installed:

```bash
cosign verify docker.io/turnerrainer/tim:0.1.0-alpha.1 \
  --certificate-identity-regexp '(?i)https://github\.com/turnerrainer/tim/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Next

- [Configure OAuth2 providers](./oauth2.md).
- [Read the full config reference](./reference/config.md).
- [Understand every HTTP status TIM returns](./failure-modes.md).
- [Harden for production](./security-hardening.md).
