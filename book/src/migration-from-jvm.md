# Migrating from JVM TIM

This chapter documents every observable difference between
TIM-on-Rust and the two upstream Java implementations:

- **Original Buerokratt TIM** (Java / Spring Boot, JVM 1.x).
- **Buerostack JVM 2.0** (Java / Spring Boot 3.3.3 rewrite).

If you are migrating an existing deployment, use this as a
per-endpoint checklist. Every deviation was surfaced during the
post-alpha audit; see the CHANGELOG entry for `[0.2.0-alpha.1]`
for the full change list.

## Endpoint availability matrix

| Endpoint | Buerokratt JVM 1.x | Buerostack JVM 2.0 | TIM-on-Rust |
|---|---|---|---|
| `GET /health` | yes | yes | yes |
| `GET /jwt/keys/public` | yes (wrapped) | yes (wrapped) | yes (bare JWKS, RFC 7517) |
| `POST /jwt/custom/generate` | (was `/jwt/custom-jwt-generate`) | yes | yes, admin-gated |
| `POST /jwt/custom/validate` | via `/custom-jwt-verify` | yes | yes |
| `POST /jwt/custom/validate/boolean` | — | yes | yes |
| `POST /jwt/custom/revoke` | via `/custom-jwt-blacklist` | yes | yes, admin-gated |
| `POST /jwt/custom/revoke/bulk` | — | yes | yes, admin-gated |
| `POST /jwt/custom/extend` | via `/custom-jwt-extend` | yes | yes, admin-gated |
| `POST /jwt/custom/list/me` | — | yes | yes |
| `POST /introspect` | — | yes | yes |
| `GET /introspect/types` | — | yes | yes |
| `GET /auth/providers` | (implicit) | yes | yes |
| `GET /auth/login/{id}` | via Spring Security OAuth2 | yes | yes |
| `GET /auth/callback/{id}` | via `/authenticate` | yes | yes (**+ real ID-token verification**) |
| `GET /auth/session/validate` | — | yes | yes |
| `GET /auth/profile` | via `/userinfo` (cookie) | yes | yes |
| `POST /auth/logout` | via `/logout` | yes | yes |
| **`GET /jwt/userinfo`** | yes (cookie) | dropped | **restored** (legacy, public) |
| **`POST /jwt/blacklist`** | yes | dropped | **restored** (legacy, admin-gated) |
| **`POST /jwt/custom-jwt-blacklist`** | yes | dropped | **restored** (legacy, admin-gated) |

The three restored legacy endpoints are documented in
[Legacy compatibility](./legacy-compat.md). They coexist with the
modern shapes; nothing was replaced.

## Response-shape changes

### `POST /jwt/custom/generate`

| Field | JVM 2.0 | TIM-on-Rust |
|---|---|---|
| `status` | `"created"` | `"created"` ← parity restored |

TIM-on-Rust 0.1.0-alpha.1 briefly returned `"ok"`; the current build
returns `"created"` to match JVM 2.0.

### `POST /jwt/custom/extend`

| Field | JVM 2.0 | TIM-on-Rust |
|---|---|---|
| `status` | `"extended"` | `"extended"` ← parity restored |
| `jwt_name` on missing | `"EXTENDED_TOKEN"` | `"EXTENDED_TOKEN"` ← parity restored |
| Default `expirationInMinutes` | 60 | 60 ← parity restored |
| HTTP on expired/revoked | 401 | 422 (Rust chose 422 as more precise; JVM callers switching on 401 need to add 422 to their branch) |

### `POST /jwt/custom/revoke`

| Situation | JVM 2.0 | TIM-on-Rust |
|---|---|---|
| Newly revoked | 200 `{"status": "revoked"}` | 200 `{"status": "revoked", "message": "..."}` |
| Idempotent repeat | 409 `{"status": "already_revoked"}` | 409 `{"status": "already_revoked", "message": "..."}` |

Parity restored.

### `POST /jwt/custom/validate`

| Situation | JVM 2.0 | TIM-on-Rust |
|---|---|---|
| Valid + active | 200 | 200 |
| Invalid or revoked | **401** with response body | **401** ← parity restored |

Callers that assumed 200 for every response now need to check HTTP
status. The response body's `valid`/`active` fields still tell the
full story.

### `POST /jwt/custom/list/me`

| Field | JVM 2.0 | TIM-on-Rust |
|---|---|---|
| Request `offset` | page number | page number (opt into row-offset with `by_row: true`) |
| Request `limit` | page size (default 20) | page size (default 20) |
| Request `jwtName` | accepted (JVM bug: silently ignored) | accepted and honoured |
| Response `page` | present | present |
| Response `size` | present | present |
| Response `total_pages` | present | present |
| Response `offset` | absent | additionally present (row offset) |
| Response `limit` | absent | additionally present (page size) |
| Denylist check | yes | yes ← now checked (was missing in initial Rust cut) |

### `GET /jwt/keys/public`

| Shape | JVM 2.0 | TIM-on-Rust |
|---|---|---|
| Response | `{"jwk": "<stringified JWKS>"}` | `{"keys": [...]}` (bare RFC 7517 JWKS) |

**Breaking difference** kept for RFC-correctness. Clients that
unwrapped `.jwk` and parsed the inner string must switch to parsing
the top-level `keys` directly.

## OAuth2 flow changes

### ID-token verification

**JVM 2.0** — `JwtValidationService.validateIdToken` verifies
signature, `iss`, `aud`, `exp`, `nbf`, `iat`, and nonce.

**TIM-on-Rust 0.1.0-alpha.1** — did not verify signature at all
(critical bug fixed post-alpha.1).

**Current** — matches JVM 2.0 behaviour and adds: constant-time
nonce comparison, mandatory nonce presence, refusal of `alg=none`
and symmetric algorithms.

### Session storage

**JVM 2.0** — in-process `ConcurrentHashMap`; no persistence.

**TIM-on-Rust 0.1.0-alpha.1** — same, but the config knob was
silently ignored.

**Current** — `oauth2.session_store: "memory" | "postgres"`. Postgres
mode persists across restart, spans replicas, encrypts profile
data at rest with chacha20poly1305.

### Session TTL

**JVM 2.0** — `min(24h, expires_in)`.

**TIM-on-Rust 0.1.0-alpha.1** — `expires_in` unbounded.

**Current** — `min(oauth2.session_ttl_seconds, expires_in)`. Matches
JVM's cap semantics.

### `redirect_uri` handling

**Buerokratt / JVM 2.0** — hard-coded `http://localhost:8085/...`
(TODO comment in both).

**TIM-on-Rust 0.1.0-alpha.1** — accepted any caller-supplied value
without validation.

**Current** — per-provider `allowed_redirect_uris` allow-list;
falls back to `{server.public_base_url}/auth/callback/{id}`. Invalid
input rejected 400.

### Callback error handling

**JVM 2.0** — accepts `error=` param, bubbles to caller.

**TIM-on-Rust 0.1.0-alpha.1** — required `code=`, so IdP-returned
errors surfaced as "missing field code" 400s.

**Current** — matches JVM.

### `auth.oauth_state` hygiene

**JVM 2.0** — in-memory state, 5-minute expiry checked in
`validateCallback`.

**TIM-on-Rust 0.1.0-alpha.1** — DB-backed state, no age check, no
sweep — rows accumulated indefinitely.

**Current** — DB-backed state with 5-minute default age cap
(`oauth2.state_max_age_seconds`) enforced in the `DELETE ...
RETURNING` clause, plus a background sweeper every
`oauth2.session_sweep_interval_seconds`.

## Config surface — new fields

| Field | Purpose | Default |
|---|---|---|
| `server.public_base_url` | External TIM URL; used for default callback synthesis | `""` |
| `database.acquire_timeout_seconds` | Pool timeout knob | 30 |
| `database.idle_timeout_seconds` | Pool timeout knob | 600 |
| `database.max_lifetime_seconds` | Pool timeout knob | 1800 |
| `jwt.cookie_name` | Cookie name for legacy endpoints | `"jwt"` |
| `oauth2.state_max_age_seconds` | oauth_state row max age | 300 |
| `oauth2.session_sweep_interval_seconds` | Sweeper interval | 60 |
| `oauth2.session_encryption_key_env` | Env var for AEAD key | `"TIM_SESSION_ENCRYPTION_KEY"` |
| `oauth2.providers.<id>.allowed_redirect_uris` | Per-provider allow-list | `[]` |
| `security.admin_token_env` | Env var for admin token | `"TIM_ADMIN_TOKEN"` (empty in defaults) |
| `security.require_admin_token` | Refuse boot if unresolved | `true` |
| `security.cors_allowed_origins` | CORS origin list | `[]` |
| `security.content_security_policy` | CSP header | (see [Security hardening](./security-hardening.md)) |
| `security.strict_transport_security` | HSTS header | (see [Security hardening](./security-hardening.md)) |
| `security.referrer_policy` | Referrer-Policy header | `"no-referrer"` |
| `security.x_frame_options` | X-Frame-Options header | `"DENY"` |
| `security.x_content_type_options` | X-Content-Type-Options header | `"nosniff"` |

## Migration checklist

For each existing JVM 2.0 deployment:

1. Generate an admin token and set `TIM_ADMIN_TOKEN` in the
   environment.
2. Set `server.public_base_url` in `tim.yaml`.
3. For every provider block, add
   `allowed_redirect_uris: [<canonical URL>]`.
4. Decide session store: keep `memory` (single replica) or switch to
   `postgres` (multi replica). If Postgres, generate a 32-byte hex
   key and set `TIM_SESSION_ENCRYPTION_KEY`.
5. Update client-side callers that switched on `body.status ==
   "ok"` — the value is now `"created"` for generate and
   `"extended"` for extend.
6. Update client-side callers that expected 200 for every validate
   response — invalid tokens now return 401.
7. Update client-side callers that expected 200 for idempotent
   revokes — repeat revocations now return 409.
8. If you consume `/jwt/keys/public`, unwrap the JVM's
   `{"jwk": "..."}` wrapper — TIM-on-Rust returns the bare JWKS.
9. If any Ruuter DSL calls `/jwt/userinfo`, `/jwt/blacklist`, or
   `/jwt/custom-jwt-blacklist`, no changes are required — those
   endpoints are still present. See
   [Legacy compatibility](./legacy-compat.md).

For deployments coming from **Buerokratt JVM 1.x** (not 2.0),
additionally:

- Rename all endpoint calls per the table at the top of this page.
- The `UserInfo` shape from the original `/jwt/userinfo` has been
  simplified — Estonian-specific fields (channel type, personal ID)
  are gone; extract them from the `claims` map instead.
- IP allow-listing (`security.allowlist.jwt`) is not implemented;
  gate at the reverse proxy or rely on the admin token.
