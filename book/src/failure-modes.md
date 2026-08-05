# Failure modes

Every HTTP status TIM can return, and what caused it.

## Framework-level

| Status | Cause | Response body |
|---|---|---|
| 200 | Success. | Endpoint-specific JSON. |
| 400 | Invalid JSON, missing required field, or field out of range. | `{"error":"bad_request","detail":"..."}` |
| 401 | Bearer / admin token required and missing / malformed. | `{"error":"unauthorized"}` |
| 403 | Bearer token valid but caller not permitted. | `{"error":"forbidden"}` |
| 404 | No such route, or entity not found. | `{"error":"not_found","detail":"..."}` |
| 405 | Method not allowed on that route. | `{"error":"method_not_allowed"}` |
| 408 | Request exceeded `server.request_timeout_seconds`. | `{"error":"request_timeout"}` |
| 409 | Idempotent-conflict (already-revoked / already-blacklisted). | `{"status":"already_revoked","message":"..."}` |
| 413 | Request body exceeded `server.max_request_bytes` or `jwt.max_claims_bytes`. | `{"error":"payload_too_large","max":<n>}` |
| 415 | Unsupported Content-Type (only introspect enforces this, and only when body parses in neither JSON nor form). | `{"error":"unsupported_media_type"}` |
| 422 | Semantic validation failure (invalid audience, ID token failed OIDC checks, extend of expired/revoked token). | `{"error":"unprocessable_entity","detail":"..."}` |
| 500 | Unhandled internal error. Every occurrence logs with the request ID. | `{"error":"internal_error"}` — no internals leaked. |
| 502 | Upstream (OAuth2 provider or JWKS endpoint) returned a malformed or unexpected response. | `{"error":"bad_gateway","detail":"..."}` |
| 504 | Upstream OAuth2 provider exceeded the timeout. | `{"error":"upstream_timeout","detail":"..."}` |

## Custom JWT endpoints

### `POST /jwt/custom/generate` — admin-gated

| Status | Cause |
|---|---|
| 200 | Token issued and persisted. `status: "created"`. |
| 400 | Missing `JWTName`, missing / invalid `expirationInMinutes`, malformed `content`. |
| 401 | Admin token missing or wrong. |
| 413 | `content` payload larger than `jwt.max_claims_bytes`. |
| 422 | `audience` present but validation is enabled and none of the values are in `jwt.audience.allowed`. |

### `POST /jwt/custom/validate` and `/validate/boolean`

| Status | Cause |
|---|---|
| 200 | Token verified and active. |
| 401 | Token invalid, expired, or revoked — the response body's `reason` field explains why. |
| 400 | Missing `token` field. |

Response body carries `valid` + `active`:

- `valid: true, active: true` — signature OK, not expired, not revoked → HTTP 200.
- `valid: true, active: false, reason: "expired"` → HTTP 401.
- `valid: true, active: false, reason: "revoked"` → HTTP 401.
- `valid: false, reason: "signature_mismatch"` → HTTP 401.
- `valid: true, active: false, reason: "audience_mismatch"` → HTTP 401.
- `valid: true, active: false, reason: "issuer_mismatch"` → HTTP 401.

The `/validate/boolean` variant returns plain `true`/`false` in the
body with the same status semantics.

### `POST /jwt/custom/revoke` — admin-gated

| Status | Cause |
|---|---|
| 200 | Token added to denylist. `{"status":"revoked","message":"..."}` |
| 409 | Already denylisted. `{"status":"already_revoked","message":"..."}` |
| 400 | Missing `token` field, or token signature invalid. |
| 401 | Admin token missing or wrong. |

### `POST /jwt/custom/revoke/bulk` — admin-gated

| Status | Cause |
|---|---|
| 200 | Every token in the batch newly revoked. |
| 207 | Multi-status: mix of newly / already / failed. |
| 409 | All tokens were already revoked (nothing changed). |
| 400 | `tokens` empty, larger than `jwt.bulk_revoke_max`, or every token failed. |
| 401 | Admin token missing or wrong. |

Response body:

```json
{
  "newly_revoked": 3,
  "already_revoked": 1,
  "failed": 2,
  "results": [
    {"token": "eyJhbGciOi...", "status": "revoked"},
    {"token": "eyJhbGciOi...", "status": "already"},
    {"token": "eyJhbGciOi...", "status": "failed", "reason": "malformed"}
  ]
}
```

### `POST /jwt/custom/extend` — admin-gated

| Status | Cause |
|---|---|
| 200 | New token issued, old token added to denylist. `status: "extended"`. |
| 400 | Missing `token` field. |
| 401 | Admin token missing or wrong. |
| 422 | Old token is already expired or revoked. |

### `POST /jwt/custom/list/me`

| Status | Cause |
|---|---|
| 200 | Paginated result. |
| 401 | Missing / malformed `Authorization: Bearer <jwt>` header, or the bearer JWT is revoked / expired / has an invalid signature. |
| 400 | `limit` > 200 or `offset` negative. |

## Legacy compat endpoints

### `GET /jwt/userinfo` — public

| Status | Cause |
|---|---|
| 200 | Cookie present and JWT valid. Response body carries `userinfo` object. |
| 400 | `Cookie` header absent, or the named cookie missing. |
| 401 | Cookie present but JWT revoked / expired / bad signature. |

### `POST /jwt/custom-jwt-blacklist` — admin-gated

| Status | Cause |
|---|---|
| 200 | `{"status":"blacklisted"}`. |
| 409 | `{"status":"already_blacklisted"}`. |
| 404 | Named cookie not present on the request. |
| 400 | Body empty, or JWT signature invalid. |
| 401 | Admin token missing or wrong. |

### `POST /jwt/blacklist` — admin-gated

| Status | Cause |
|---|---|
| 200 | Custom JWT (cookie / jti) newly revoked OR session (sessionId) logged out. |
| 409 | Custom JWT already revoked. |
| 404 | Jti mode: no TIM-issued JWT with that jti. Session mode: no such session. |
| 400 | None of the three parameter modes supplied; or `?jwt=<uuid>` value not a valid UUID; or cookie JWT unparseable. |
| 401 | Admin token missing or wrong. |

## OAuth2 endpoints

### `GET /auth/login/{provider_id}`

| Status | Cause |
|---|---|
| 200 | Authorization URL returned. |
| 400 | Caller-supplied `redirect_uri` not on the provider's allow-list. |
| 400 | No `redirect_uri` supplied and neither the allow-list nor `server.public_base_url` yield a default. |
| 404 | Unknown provider ID. |
| 502 | Upstream discovery fetch failed (after retries). |
| 504 | Discovery fetch timed out. |

### `GET /auth/callback/{provider_id}`

| Status | Cause |
|---|---|
| 200 | Session created. |
| 400 | Missing `code` or `state` query param. |
| 400 | IdP returned `error=` — body includes `error` and `error_description` from the provider. |
| 404 | Unknown provider ID. |
| 422 | State does not match a persisted state row (CSRF / replay / expired past `state_max_age_seconds`). |
| 422 | Token response has no `id_token`. |
| 422 | ID-token verification failed (bad `iss`, `aud`, `nonce`, signature, `exp`, `nbf`, `iat`; symmetric or `alg=none` refused; `kid` not in JWKS). |
| 502 | Token exchange with provider failed / JWKS fetch failed. |
| 504 | Token exchange timed out. |

### `GET /auth/session/validate` and `/profile`

| Status | Cause |
|---|---|
| 200 | Session found; body indicates `valid` + expiry. |
| 401 | No session ID supplied via any of the three transports. |
| 404 | Session not found or expired. |

### `POST /auth/logout`

| Status | Cause |
|---|---|
| 200 | Session existed and was revoked, OR unknown session (idempotent). Body's `status` distinguishes. |
| 401 | No session ID supplied. |

Note: unlike blacklist, logout intentionally does not 404 for unknown
sessions — a browser retry after network flakiness shouldn't produce
a spurious error surface.

## Introspection

### `POST /introspect`

| Status | Cause |
|---|---|
| 200 | Standard RFC 7662 response (may report `active: false`). |
| 400 | Missing `token` in body, or body parses in neither JSON nor form. |

The response never distinguishes "unknown token" from "revoked
token" — both are bare `{"active": false}` per RFC 7662 §2.2, on
every failure path.

## Framework

### `GET /health`

Always `200 {"status":"ok"}` — a 200 here proves the process is
alive and can bind. It does NOT prove database connectivity;
database problems surface as 500 on the actual endpoints. This is
deliberate — a "deep" healthcheck that hits the DB would take TIM
down as a side effect of DB blips.

### `GET /auth/health`

Reports the OAuth2 registry status: available providers, provider
IDs, timestamp. Always 200 unless TIM itself is unhealthy.

## Response headers on every response

Every response (including error paths and 404s) carries the security
headers configured in `security.*`. Default set:

```
content-security-policy: default-src 'none'; frame-ancestors 'none'
strict-transport-security: max-age=63072000; includeSubDomains
referrer-policy: no-referrer
x-frame-options: DENY
x-content-type-options: nosniff
```

Empty strings in the config skip a given header. See
[Security hardening](./security-hardening.md#http-response-headers).
