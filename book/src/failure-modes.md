# Failure modes

Every HTTP status TIM can return, and what caused it.

## Framework-level

| Status | Cause | Response body |
|---|---|---|
| 200 | Success. | Endpoint-specific JSON. |
| 400 | Invalid JSON, missing required field, or field out of range. | `{"error":"bad_request","detail":"..."}` |
| 401 | Bearer token required and missing / malformed. | `{"error":"unauthorized"}` |
| 403 | Bearer token valid but caller not permitted (bulk-revoke of tokens the caller does not own). | `{"error":"forbidden"}` |
| 404 | No such route, or entity not found (unknown provider ID, unknown session). | `{"error":"not_found"}` |
| 408 | Request exceeded `server.request_timeout_seconds`. | `{"error":"request_timeout"}` |
| 413 | Request body exceeded `server.max_request_bytes` or `jwt.max_claims_bytes`. | `{"error":"payload_too_large","max":<n>}` |
| 415 | Unsupported `Content-Type` (introspect accepts `application/x-www-form-urlencoded` or `application/json`). | `{"error":"unsupported_media_type"}` |
| 422 | Semantic validation failure (invalid audience, extension of already-revoked token). | `{"error":"unprocessable_entity","detail":"..."}` |
| 500 | Unhandled internal error. Every occurrence is logged with the request ID. | `{"error":"internal_error"}` — no internals leaked. |
| 502 | Upstream (OAuth2 provider) returned a malformed or unexpected response. | `{"error":"bad_gateway","provider":"<id>"}` |
| 504 | Upstream (OAuth2 provider) exceeded the timeout. | `{"error":"upstream_timeout","provider":"<id>"}` |

## Custom JWT endpoints

### `POST /jwt/custom/generate`

| Status | Cause |
|---|---|
| 200 | Token issued and persisted. |
| 400 | Missing `JWTName`, missing / invalid `expirationInMinutes`, malformed `content`. |
| 413 | `content` payload larger than `jwt.max_claims_bytes`. |
| 422 | `audience` present but validation is enabled and none of the values are in `jwt.audience.allowed`. |

### `POST /jwt/custom/validate` and `/validate/boolean`

| Status | Cause |
|---|---|
| 200 | Response body carries the verdict (never a non-2xx for "invalid" — invalidity is a normal, expected result). |
| 400 | Missing `token` field. |

The response body's `valid` and `active` fields tell you what
happened:

- `valid: true, active: true` — signature OK, not expired, not revoked.
- `valid: true, active: false, reason: "expired"` — signature OK, expired.
- `valid: true, active: false, reason: "revoked"` — signature OK, denylisted.
- `valid: false, reason: "signature_mismatch"` — signature failure.
- `valid: false, reason: "malformed"` — not a parseable JWT.
- `valid: true, active: false, reason: "audience_mismatch"` — audience validation is enabled and the token's `aud` is not in the allowed set.
- `valid: true, active: false, reason: "issuer_mismatch"` — request asked for a specific issuer and the token's `iss` does not match.

### `POST /jwt/custom/revoke`

| Status | Cause |
|---|---|
| 200 | Token added to denylist (idempotent — already-revoked tokens return 200 with `already: true`). |
| 400 | Missing `token`. |

### `POST /jwt/custom/revoke/bulk`

| Status | Cause |
|---|---|
| 200 | All tokens processed. Response body has per-token results. |
| 207 | Multi-status: some tokens revoked, some failed. Same response body shape. |
| 400 | `tokens` is empty or larger than `jwt.bulk_revoke_max`. |

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

### `POST /jwt/custom/extend`

| Status | Cause |
|---|---|
| 200 | New token issued, old token added to denylist. |
| 400 | Missing `token`. |
| 422 | Old token is already expired or revoked. |

### `POST /jwt/custom/list/me`

| Status | Cause |
|---|---|
| 200 | Paginated result. |
| 401 | Missing / malformed `Authorization: Bearer <jwt>` header. |
| 400 | `limit` > 200 or `offset` negative. |

## OAuth2 endpoints

### `GET /auth/login/{provider_id}`

| Status | Cause |
|---|---|
| 200 | Authorization URL returned. |
| 404 | Unknown provider ID. |
| 502 | Provider discovery not yet cached and upstream fetch failed. |

### `GET /auth/callback/{provider_id}`

| Status | Cause |
|---|---|
| 200 | Session created. |
| 400 | Missing `code` or `state` query param. |
| 404 | Unknown provider ID. |
| 422 | State does not match a persisted state row (CSRF / replay). |
| 422 | ID token validation failed (bad `iss` / `aud` / `nonce` / signature / `exp`). |
| 502 | Token exchange with provider failed. |
| 504 | Token exchange with provider timed out. |

### `GET /auth/session/validate` and `/profile`

| Status | Cause |
|---|---|
| 200 | Session found, response body indicates `valid` + expiry. |
| 400 | Missing `session_id` query param. |
| 404 | Session not found or expired. |

### `POST /auth/logout`

| Status | Cause |
|---|---|
| 200 | Session invalidated (idempotent — unknown sessions return 200). |
| 400 | Missing `session_id` query param. |

## Introspection

### `POST /introspect`

| Status | Cause |
|---|---|
| 200 | Standard RFC 7662 response (may report `active: false`). |
| 400 | Missing `token` in form or JSON body. |
| 415 | Unsupported `Content-Type`. |

The response never distinguishes "unknown token" from "revoked
token" — both are `{"active": false}` per RFC 7662 §2.2 to avoid
information leaks.

## Framework

### `GET /health`

Always `200 {"status":"ok"}` — a 200 here proves the process is
alive and can bind. It does NOT prove database connectivity;
database problems surface as 500 on the actual endpoints. This is
deliberate — a "deep" healthcheck that hits the DB would take TIM
down as a side effect of DB blips.
