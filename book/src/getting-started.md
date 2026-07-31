# Getting started

Five-minute install from an empty machine to first JWT.

## 1. Prerequisites

- Docker 20+ with Docker Compose v2 (`docker compose ...`).
- `curl`.
- `openssl` (only for generating a demo signing key — you already
  have this on every modern *nix).

Nothing else. TIM's runtime is a self-contained container image.

## 2. Get the source (only for local build)

If you just want the published image, skip to step 3.

```bash
git clone https://github.com/turnerrainer/tim.git
cd tim
```

## 3. Generate a demo RSA signing key

TIM signs JWTs with RS256. Generate a PKCS#8 PEM keypair — the
private half is what TIM loads; the public half is derived and
published automatically at `/jwt/keys/public`.

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out keys/jwt-private.pem
```

Never commit this file. It is a secret. `.gitignore` already
excludes `*.pem` outside `tests/fixtures/`.

## 4. Bring TIM + Postgres up

```bash
export TIM_DATABASE_PASSWORD=demo-only-do-not-use-in-prod
docker compose up -d
```

Docker Compose starts:

- **`tim-postgres`** — PostgreSQL 16, port 5432 on host.
- **`tim`** — TIM API server, port 8085 on host.

TIM waits for Postgres to be healthy, runs SQL migrations on first
boot, and starts serving.

## 5. Verify the install

Health check:

```bash
curl -sf http://localhost:8085/health
# {"status":"ok"}
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

## 6. Generate your first JWT

```bash
TOKEN=$(curl -sX POST http://localhost:8085/jwt/custom/generate \
  -H 'content-type: application/json' \
  -d '{"JWTName":"welcome","content":{"sub":"you"},"expirationInMinutes":15}' \
  | jq -r .token)
echo "$TOKEN"
```

Decode the payload:

```bash
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

Validate:

```bash
curl -sX POST http://localhost:8085/jwt/custom/validate \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$TOKEN\"}" | jq
```

Response includes `valid: true`, `active: true`, the subject, and
the full claim map.

## 7. Introspect (RFC 7662)

```bash
curl -sX POST http://localhost:8085/introspect \
  -d "token=$TOKEN" | jq
```

## 8. Revoke

```bash
curl -sX POST http://localhost:8085/jwt/custom/revoke \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"reason\":\"demo cleanup\"}"
```

Re-validate — `valid: false`, `reason: "revoked"`.

## 9. Verify the image cosign signature (optional, recommended)

Every published tag is signed keyless via cosign. From a machine
with `cosign` installed:

```bash
cosign verify docker.io/turnerrainer/tim:0.1.0-alpha.1 \
  --certificate-identity-regexp 'https://github.com/turnerrainer/tim/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Next

- [Configure OAuth2 providers](./oauth2.md).
- [Read the full config reference](./configuration.md).
- [Understand every HTTP status TIM returns](./failure-modes.md).
