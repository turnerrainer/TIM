# 16 — `TokenResponse.status` and revoke/HTTP semantics diverge from JVM

**Severity:** MEDIUM (API compatibility)
**Area:** Custom JWT / API
**Files:**

- `src/jwt/service.rs:120-125` (generate)
- `src/jwt/service.rs:438-444` (extend)
- `src/router/mod.rs:107-116` (revoke)

## What happens

Multiple response fields and HTTP status codes changed silently.

### `POST /jwt/custom/generate`

| Field / status | Java (`CustomJwtController.java:64`) | Rust (`jwt/service.rs:120-125`) |
|---|---|---|
| `status` value | `"created"` | `"ok"` |
| HTTP code      | 200                                   | 200                              |

### `POST /jwt/custom/extend`

| Field / status | Java (`CustomJwtController.java:287`) | Rust (`jwt/service.rs:438-444`) |
|---|---|---|
| `status` value | `"extended"`                          | `"ok"`                           |
| `jwt_name`     | `"EXTENDED_TOKEN"` literal            | Passed-through original name (or `""` if the DB has none) |
| HTTP code on expired / revoked | 401 (`extend_denied`)     | 422 (`unprocessable_entity`)     |
| HTTP code on other errors | 400 (`extend_failed`)          | 500 (`internal_error`)           |

### `POST /jwt/custom/revoke`

| Situation | Java (`CustomJwtController.java:141-159`) | Rust (`router/mod.rs:107-116`) |
|---|---|---|
| Newly revoked  | 200 `{"status": "revoked", "message": "..."}`       | 200 `{"status": "revoked", "already": false}` |
| Already revoked | 409 `{"status": "already_revoked", "message": "..."}` | **200** `{"status": "already", "already": true}` |
| Extra field | `message` (human-readable)                           | `already` (boolean)               |

## Reference — Buerostack Java TIM

See the linked line ranges above. The status-string and status-code
choices are visible surface — a client that switches on `body.status`
or `response.status()` will break.

## Impact

- Clients that check `if (resp.status == "created")` on generate now
  see `"ok"` and take the failure branch.
- Clients that treat 409 as "already revoked" (idempotent no-op)
  now see 200 and assume they were the ones who revoked it.
- Human-readable `message` fields are gone; error diagnosis by
  humans reading server logs / HAR captures is harder.
- No entry in `CHANGELOG.md` warning of the break.
