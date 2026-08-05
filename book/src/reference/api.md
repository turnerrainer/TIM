# API reference

Compact, endpoint-by-endpoint reference. Every route TIM exposes,
its method, the auth it requires, and the input/output shape.

For failure paths and status-code semantics, see
[Failure modes](../failure-modes.md).

## Auth legend

| Symbol | Meaning |
|---|---|
| — | Public (no credentials required). |
| **admin** | Requires `X-TIM-Admin-Token: <secret>` or `Authorization: Bearer <secret>`. |
| **bearer** | Requires `Authorization: Bearer <TIM-issued JWT>` — signature, exp, and denylist checked. |
| **session** | Requires `Authorization: Bearer sess_<id>`, `X-TIM-Session: <id>`, or legacy `?session_id=<id>`. |
| **cookie** | Requires `Cookie: <jwt.cookie_name>=<TIM-issued JWT>`. |

## Framework

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | — | Liveness check. Always `{"status":"ok"}`. |

## Custom JWT

| Route | Auth | Purpose |
|---|---|---|
| `POST /jwt/custom/generate` | admin | Issue a new JWT. |
| `POST /jwt/custom/validate` | — | Structured validation (returns 401 when inactive). |
| `POST /jwt/custom/validate/boolean` | — | Plain-text `true`/`false`, same auth semantics. |
| `POST /jwt/custom/revoke` | admin | Single-token denylist. 200 new, 409 already. |
| `POST /jwt/custom/revoke/bulk` | admin | Up to `jwt.bulk_revoke_max` per call. |
| `POST /jwt/custom/extend` | admin | Reissue with preserved claims; old goes to denylist. |
| `POST /jwt/custom/list/me` | bearer | Paginated own-token list. |
| `GET /jwt/keys/public` | — | RFC 7517 JWKS with the signing public key. |

### `POST /jwt/custom/generate`

Request:

```json
{
  "JWTName": "session-token",
  "content": {
    "sub": "user-42",
    "role": "admin"
  },
  "expirationInMinutes": 60,
  "audience": "downstream-api",
  "setCookie": false
}
```

- `JWTName` (required) — free-form label; stored in metadata.
- `content` (required) — map of claim-name → JSON value. `sub` is
  extracted into the signed `sub` claim; all other keys land in
  the flatten-extras. Reserved names (`iss`, `aud`, `exp`, `iat`,
  `jti`, `nbf`) are stripped. `token_type: "custom_jwt"` is injected
  automatically.
- `expirationInMinutes` (required, > 0).
- `audience` (optional) — string or list of strings.
- `setCookie` (optional bool) — if true, the response carries
  `Set-Cookie: <JWTName>=<token>; Path=/; HttpOnly; Secure; SameSite=Lax`.

Also accepts snake-case aliases: `jwt_name`, `expiration_in_minutes`,
`set_cookie`.

Response (200):

```json
{
  "status": "created",
  "jwt_name": "session-token",
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...",
  "expires_at": "2026-08-04T13:34:56Z"
}
```

### `POST /jwt/custom/validate`

Request:

```json
{
  "token": "eyJhbGciOi...",
  "audience": "expected-aud",
  "issuer": "TIM",
  "reason": null
}
```

`audience` and `issuer` are optional expectations; when set, TIM
enforces them and returns `audience_mismatch` / `issuer_mismatch`
on failure.

Response (200 when active, 401 when not):

```json
{
  "valid": true,
  "active": true,
  "reason": null,
  "subject": "user-42",
  "issuer": "TIM",
  "audience": ["tim-service"],
  "expires_at": "2026-08-04T13:34:56Z",
  "issued_at": "2026-08-04T12:34:56Z",
  "jwt_id": "0e2b...-uuid",
  "claims": { "role": "admin", "token_type": "custom_jwt" }
}
```

`reason` is one of: `"expired"`, `"revoked"`, `"signature_mismatch"`,
`"audience_mismatch"`, `"issuer_mismatch"`.

### `POST /jwt/custom/validate/boolean`

Same request. Response body is plain `true` or `false` with
`Content-Type: text/plain`. HTTP status is 200 when true, 401 when
false.

### `POST /jwt/custom/revoke`

Request:

```json
{ "token": "eyJhbGciOi...", "reason": "user logout" }
```

Response 200:

```json
{ "status": "revoked", "message": "Token has been successfully revoked" }
```

Response 409 (idempotent repeat):

```json
{ "status": "already_revoked", "message": "Token was already revoked" }
```

### `POST /jwt/custom/revoke/bulk`

Request:

```json
{ "tokens": ["eyJhbGciOi...", "eyJhbGciOi...", "..."], "reason": "batch" }
```

Response 200 / 207 / 409 / 400 depending on outcome. See
[Failure modes](../failure-modes.md#post-jwtcustomrevokebulk).

### `POST /jwt/custom/extend`

Request:

```json
{ "token": "eyJhbGciOi...", "expirationInMinutes": 30, "setCookie": true }
```

`expirationInMinutes` defaults to 60. `setCookie: true` adds
`Set-Cookie: EXTENDED_TOKEN=<new>; Path=/; HttpOnly; Secure;
SameSite=Lax`.

Response 200:

```json
{
  "status": "extended",
  "jwt_name": "session-token",
  "token": "eyJhbGciOi...",
  "expires_at": "2026-08-04T14:04:56Z"
}
```

### `POST /jwt/custom/list/me`

Bearer authentication required. Request body optional:

```json
{
  "offset": 0,
  "limit": 20,
  "byRow": false,
  "issuedAfter": "2026-07-01T00:00:00Z",
  "issuedBefore": null,
  "expiresAfter": null,
  "expiresBefore": null,
  "jwtName": null
}
```

Semantics — `offset` is a *page number* by default (JVM parity).
Set `byRow: true` to interpret `offset` as a row offset instead.
`limit` is page size (cap 200).

Response:

```json
{
  "tokens": [
    {
      "jti": "0e2b...-uuid",
      "subject": "user-42",
      "jwt_name": "session-token",
      "issued_at": "2026-08-04T12:34:56Z",
      "expires_at": "2026-08-04T13:34:56Z",
      "issuer": "TIM",
      "audience": "tim-service",
      "status": "active"
    }
  ],
  "pagination": {
    "total": 42,
    "offset": 0,
    "limit": 20,
    "page": 0,
    "size": 20,
    "total_pages": 3
  }
}
```

Both pagination shapes are populated concurrently for parity with
either JVM or row-based clients.

### `GET /jwt/keys/public`

No request body. Response is a bare RFC 7517 JWKS:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "tim-rs-1",
      "n": "0vx7ag...",
      "e": "AQAB"
    }
  ]
}
```

Note: differs from the JVM 2.0 shape which wrapped this in
`{"jwk": "<stringified>"}`. See
[Migrating from JVM TIM](../migration-from-jvm.md#get-jwtkeyspublic).

## Introspection

| Route | Auth | Purpose |
|---|---|---|
| `POST /introspect` | — | RFC 7662 introspection. Accepts JSON or form. |
| `GET /introspect/types` | — | Supported token types. |

### `POST /introspect`

Accepts one of:

- `Content-Type: application/x-www-form-urlencoded` — body
  `token=<jwt>&token_type_hint=<optional>`.
- `Content-Type: application/json` — body `{"token": "...", "token_type_hint": "..."}`.
- No or unknown Content-Type — TIM tries JSON, then form (best-effort
  parse).

Response 200 for active tokens:

```json
{
  "active": true,
  "iss": "TIM",
  "sub": "user-42",
  "aud": ["tim-service"],
  "exp": 1723456789,
  "iat": 1723453189,
  "jti": "0e2b...-uuid",
  "token_type": "custom_jwt",
  "extra_claims": { "role": "admin" }
}
```

Every inactive path (unknown, revoked, expired, wrong issuer, bad
signature) returns bare `{"active": false}` per RFC 7662 §2.2.

## OAuth2 / OIDC

| Route | Auth | Purpose |
|---|---|---|
| `GET /auth/providers` | — | List configured providers. |
| `GET /auth/providers/{id}` | — | One provider's public config. |
| `GET /auth/login/{id}` | — | Start authorization code flow. |
| `GET /auth/callback/{id}` | — | Complete flow (called by IdP redirect). |
| `GET /auth/session/validate` | session | Verify + touch. |
| `GET /auth/profile` | session | Return canonical profile map. |
| `POST /auth/logout` | session | Revoke session. Body may include `{"reason":"..."}`. |
| `GET /auth/health` | — | Registry / provider status. |

Session transports (accepted on any `session`-marked endpoint):

- `Authorization: Bearer sess_<id>`
- `X-TIM-Session: <id>`
- `?session_id=<id>` (legacy)

## Legacy compat (Buerokratt shape)

| Route | Auth | Purpose |
|---|---|---|
| `GET /healthz` | — | Alias for `GET /health`. |
| `GET /jwt/verification-key` | — | PEM-formatted JWT signing public key. |
| `GET /jwt/userinfo` | cookie | Decode cookie JWT → subject + claims. |
| `POST /jwt/custom-jwt-verify` | cookie | Verify JWT from cookie named in body. |
| `POST /jwt/custom-jwt-userinfo` | cookie | Read JWT from cookie named in body → subject + claims. |
| `POST /jwt/custom-jwt-extend` | admin + cookie | Extend JWT from cookie named in body; refresh cookie. |
| `GET /jwt/extend-jwt-session` | admin + cookie | Extend JWT from `jwt.cookie_name` cookie; refresh cookie. |
| `POST /jwt/custom-jwt-blacklist` | admin + cookie | Revoke JWT from named cookie (body = cookie name). |
| `POST /jwt/blacklist` | admin | Three modes: cookie, `?jwt=<uuid>`, `?sessionId=<id>`. |

See [Legacy compatibility](../legacy-compat.md) for full request /
response examples.
