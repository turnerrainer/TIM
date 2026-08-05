# Legacy compatibility

TIM-on-Rust keeps the eight cookie-borne and PEM-shaped endpoints
from the original Buerokratt TIM alive so the ~93 Ruuter DSL files
that reference `check-user-authority.yml` and `logout.yml` continue
to work unchanged. These endpoints coexist with the modern
header/body shapes — nothing was replaced; both surfaces hit the
same backing services.

The eight legacy endpoints and their roles:

| Path | Method | Purpose | Auth |
|---|---|---|---|
| `/healthz` | GET | Alias for `/health` (same body) | public |
| `/jwt/verification-key` | GET | Returns the JWT signing public key as PEM | public |
| `/jwt/userinfo` | GET | Read JWT from `<jwt.cookie_name>` cookie → subject + claims | public |
| `/jwt/custom-jwt-verify` | POST | Verify JWT from cookie named in body | public |
| `/jwt/custom-jwt-userinfo` | POST | Read JWT from cookie named in body → subject + claims | public |
| `/jwt/custom-jwt-extend` | POST | Extend JWT from cookie named in body; refresh cookie | admin |
| `/jwt/extend-jwt-session` | GET | Extend JWT from `<jwt.cookie_name>` cookie; refresh cookie | admin |
| `/jwt/custom-jwt-blacklist` | POST | Revoke JWT from cookie named in body | admin |
| `/jwt/blacklist` | POST | Revoke by cookie / `?jwt=<uuid>` / `?sessionId=<id>` | admin |

## Config

One knob:

```yaml
jwt:
  cookie_name: "jwt"   # matches the JVM JwtSignatureConfig.cookieName
```

Set this to whatever name your browser client / DSL uses for the JWT
cookie.

## `GET /jwt/userinfo` — public

Reads the JWT from a cookie named `<jwt.cookie_name>`, runs it
through the same authenticated-bearer path as
`POST /jwt/custom/list/me` (signature + exp + denylist check), and
returns a `UserInfo`-shaped response.

**Request:**

```
GET /jwt/userinfo HTTP/1.1
Cookie: jwt=eyJhbGciOi...
```

**Success — 200:**

```json
{
  "userinfo": {
    "subject": "user-42",
    "issuer": "TIM",
    "audience": ["tim-service"],
    "expires_at": "2026-08-04T12:34:56Z",
    "issued_at": "2026-08-04T11:34:56Z",
    "jwt_id": "0e2b...-uuid",
    "claims": {
      "role": "admin",
      "token_type": "custom_jwt",
      "any": "other custom claims here"
    }
  }
}
```

**Failure paths:**

- 400 — `Cookie` header absent, or the named cookie is not among
  the set of cookies sent.
- 401 — cookie present but the JWT is revoked, expired, or has an
  invalid signature.

Public: no admin token required.

## `POST /jwt/custom-jwt-blacklist` — admin-gated

Matches the JVM shape: the request **body** is the *name of the
cookie* whose value to revoke. The cookie itself must be present on
the request (`Cookie: <name>=<jwt>`).

**Request:**

```
POST /jwt/custom-jwt-blacklist HTTP/1.1
Cookie: jwt=eyJhbGciOi...
X-TIM-Admin-Token: <secret>
Content-Type: text/plain

jwt
```

Body may be the bare cookie name (`jwt`) or a JSON-quoted string
(`"jwt"`) — TIM trims quotes and whitespace defensively.

**Responses:**

- 200 `{"status": "blacklisted"}` — newly revoked.
- 409 `{"status": "already_blacklisted"}` — idempotent repeat.
- 404 `{"status": "not_found", "message": "..."}` — named cookie
  wasn't on the request.
- 400 — body was empty or the token couldn't be parsed.

## `POST /jwt/blacklist` — admin-gated

Three parameter modes, matching the JVM. Priority order:

1. **Cookie mode** — `Cookie: <jwt.cookie_name>=<jwt>` on the
   request. Revokes that custom JWT.
2. **Jti mode** — `?jwt=<uuid>` query param. Looks up the token's
   metadata (for its expiry timestamp) and adds to the denylist.
3. **Session mode** — `?sessionId=<id>` query param. Revokes the
   OAuth2 session.

**Request examples:**

```bash
# Cookie mode
curl -X POST http://localhost:8085/jwt/blacklist \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN" \
  -H "Cookie: jwt=eyJhbGciOi..."

# Jti mode
curl -X POST "http://localhost:8085/jwt/blacklist?jwt=0e2b1234-5678-90ab-cdef-1234567890ab" \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN"

# Session mode
curl -X POST "http://localhost:8085/jwt/blacklist?sessionId=abc123..." \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN"
```

**Responses:**

| Status | Meaning |
|---|---|
| 200 `{"status":"blacklisted"}` | Custom JWT (cookie or jti mode) newly revoked. |
| 200 `{"status":"logged_out"}` | Session mode: session existed and was revoked. |
| 409 `{"status":"already_blacklisted"}` | Idempotent repeat (cookie / jti mode). |
| 404 `{"status":"not_found"}` | Jti mode: no TIM-issued JWT with this jti. Session mode: no such session. |
| 400 | None of the three parameter modes supplied. |
| 400 | `?jwt=<uuid>` value is not a valid UUID string. |
| 400 | Cookie present but the JWT couldn't be parsed / signature fails. |

### Behavioural difference vs. the JVM

**The original JVM `/blacklist` returned 200 for every case** — even
when nothing was actually blacklisted. TIM-on-Rust returns meaningful
status codes. DSLs that unconditionally treated 200 as success are
unaffected; DSLs that treated non-200 as error should learn to
accept 409 as "already done."

## `GET /healthz` — public

Alias for `GET /health`. Same body (`{"status":"ok"}`), same
status code (200). Exists purely so JVM 1.x container healthchecks
and load-balancer probes that hit `/healthz` continue to work.

```bash
curl -sf http://localhost:8085/healthz
# {"status":"ok"}
```

## `GET /jwt/verification-key` — public

Returns the JWT signing public key as a PKCS#1 PEM string. Legacy
Java consumers that verify TIM-signed JWTs with a PEM-based parser
use this shape. The modern equivalent (`GET /jwt/keys/public`)
returns a bare RFC 7517 JWKS instead.

```bash
curl -sf http://localhost:8085/jwt/verification-key
# -----BEGIN RSA PUBLIC KEY-----
# MIIBCgKCAQEA0vx7...
# -----END RSA PUBLIC KEY-----
```

Content-Type: `text/plain`.

## `POST /jwt/custom-jwt-verify` — public

Body is the *cookie name* whose value TIM should verify. The cookie
itself must be on the request. Returns the same
`ValidateResponse` shape as `POST /jwt/custom/validate`.

```bash
curl -sX POST http://localhost:8085/jwt/custom-jwt-verify \
  -H 'Cookie: my-app-jwt=eyJhbGciOi...' \
  -d 'my-app-jwt'
# {"valid":true,"active":true,"subject":"user-42", ...}
```

Failure modes:

- Cookie present but token invalid / expired / revoked → 401 with
  `ValidateResponse` body.
- Cookie missing from request → 401 with
  `{"valid": false, "reason": "cookie_not_present"}`.
- Empty body → 400.

## `POST /jwt/custom-jwt-userinfo` — public

Body is the cookie name whose value to read. Response is a
`UserInfo`-shaped object with the JWT's claims. Differs from
`GET /jwt/userinfo` in that the caller specifies WHICH cookie —
`GET /jwt/userinfo` uses the configured `jwt.cookie_name` default.

```bash
curl -sX POST http://localhost:8085/jwt/custom-jwt-userinfo \
  -H 'Cookie: SESSION_JWT=eyJhbGciOi...' \
  -d 'SESSION_JWT'
# {
#   "userinfo": {
#     "subject": "user-42",
#     "issuer": "TIM",
#     "audience": ["tim-service"],
#     "expires_at": "...",
#     "issued_at": "...",
#     "jwt_id": "0e2b...",
#     "claims": {...}
#   },
#   "cookie_name": "SESSION_JWT"
# }
```

## `POST /jwt/custom-jwt-extend` — admin-gated

Body is the cookie name; server reads that cookie, extends the JWT,
and returns `Set-Cookie` with the fresh token under the same name.

```bash
curl -sX POST http://localhost:8085/jwt/custom-jwt-extend \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN" \
  -H 'Cookie: jwt=eyJhbGciOi...' \
  -d 'jwt' -i
# HTTP/1.1 200 OK
# set-cookie: jwt=eyJhbGciOi...NEW...; Path=/; HttpOnly; Secure; SameSite=Lax
# content-type: application/json
#
# {"status":"extended","jwt_name":"...","token":"eyJhbGciOi...NEW...","expires_at":"..."}
```

## `GET /jwt/extend-jwt-session` — admin-gated

GET-based extend for browser-flow callers. Reads the JWT from the
configured `jwt.cookie_name` cookie (default `"jwt"`) — no body,
no query param needed. Returns `Set-Cookie` with the refreshed token.

```bash
curl -sX GET http://localhost:8085/jwt/extend-jwt-session \
  -H "X-TIM-Admin-Token: $TIM_ADMIN_TOKEN" \
  -H 'Cookie: jwt=eyJhbGciOi...' -i
# HTTP/1.1 200 OK
# set-cookie: jwt=eyJhbGciOi...NEW...; Path=/; HttpOnly; Secure; SameSite=Lax
```

## Priority when a request satisfies multiple modes

Cookie takes precedence over query params. If a caller sends both
`Cookie: jwt=...` and `?jwt=<uuid>`, the cookie is used. This
matches the JVM.

## Configuration example

Minimal legacy-friendly deployment:

```yaml
jwt:
  cookie_name: "jwt"   # or whatever your DSL sets

security:
  admin_token_env: "TIM_ADMIN_TOKEN"
  require_admin_token: true
  # If browser clients hit these endpoints from another origin:
  cors_allowed_origins:
    - "https://frontpage.example.com"
```

DSL callers add the admin token once, at their outbound HTTP config
layer — no per-endpoint changes required.
