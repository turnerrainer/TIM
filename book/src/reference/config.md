# Configuration reference

Flat, alphabetised reference. Every field TIM accepts in `tim.yaml`,
its type, its default, and one line about what it does. For a
walk-through with examples, see [Configuration](../configuration.md).

## `server`

| Field | Type | Default | Description |
|---|---|---|---|
| `server.bind` | string | `"0.0.0.0"` | Bind address. |
| `server.port` | u16 | `8085` | TCP listener port. |
| `server.max_request_bytes` | usize | `1048576` | Global request body cap. |
| `server.request_timeout_seconds` | u64 | `30` | Per-request deadline. |
| `server.public_base_url` | string | `""` | Externally-reachable base URL; used to synthesise the default OAuth2 callback. |

## `database`

| Field | Type | Default | Description |
|---|---|---|---|
| `database.url_env` | string | `"TIM_DATABASE_URL"` | Env var name holding the `postgres://` URL. |
| `database.min_connections` | u32 | `2` | Pool floor. |
| `database.max_connections` | u32 | `10` | Pool ceiling. |
| `database.auto_migrate` | bool | `true` | Run `sqlx::migrate!` at startup. |
| `database.acquire_timeout_seconds` | u64 | `30` | Pool acquire timeout (0 = sqlx default). |
| `database.idle_timeout_seconds` | u64 | `600` | Idle-connection reaper (0 = sqlx default). |
| `database.max_lifetime_seconds` | u64 | `1800` | Connection max lifetime (0 = sqlx default). |

Connections are `.test_before_acquire(true)` — a stale connection
after a PgBouncer bounce is refreshed transparently.

## `jwt`

| Field | Type | Default | Description |
|---|---|---|---|
| `jwt.private_key_path` | path | `"/opt/tim/keys/jwt-private.pem"` | PKCS#8 PEM RSA private key. |
| `jwt.key_id` | string | `"tim-rs-1"` | `kid` advertised in JWS headers + JWKS. |
| `jwt.issuer` | string | `"TIM"` | `iss` claim on every issued token. |
| `jwt.audience.validation_enabled` | bool | `false` | If true, `POST /jwt/custom/generate` rejects unlisted audiences. |
| `jwt.audience.allowed` | list<string> | `[]` | Allow-list when validation is enabled. |
| `jwt.audience.default` | string | `"tim-service"` | Fallback `aud` when the caller omits one. |
| `jwt.max_claims_bytes` | usize | `32768` | Cap on custom claim payload size at generate time. |
| `jwt.bulk_revoke_max` | usize | `100` | Max tokens per `/jwt/custom/revoke/bulk` call. |
| `jwt.cookie_name` | string | `"jwt"` | Cookie name used by the legacy compat endpoints. |

## `oauth2`

| Field | Type | Default | Description |
|---|---|---|---|
| `oauth2.session_store` | string | `"memory"` | `"memory"` or `"postgres"`; anything else fails at startup. |
| `oauth2.discovery_cache_ttl_seconds` | u64 | `3600` | OIDC discovery cache TTL per provider. |
| `oauth2.session_ttl_seconds` | u64 | `86400` | Hard cap on session lifetime. |
| `oauth2.session_sweep_interval_seconds` | u64 | `60` | Background sweeper interval; 0 disables. |
| `oauth2.state_max_age_seconds` | u64 | `300` | Max age of an `auth.oauth_state` row at callback time. |
| `oauth2.session_encryption_key_env` | string | `"TIM_SESSION_ENCRYPTION_KEY"` | Env var holding the 32-byte hex AEAD key; required when `session_store: "postgres"`. |
| `oauth2.providers` | map | `{}` | Provider ID → provider config. |

### `oauth2.providers.<id>`

| Field | Type | Default | Description |
|---|---|---|---|
| `.name` | string | (required) | Human label. |
| `.discovery_url` | string | (required) | `.well-known/openid-configuration` URL. |
| `.client_id_env` | string | (required) | Env var name holding the client ID. |
| `.client_secret_env` | string | (required) | Env var name holding the client secret. |
| `.scopes` | list<string> | `["openid","profile","email"]` | Scopes to request. |
| `.claim_mappings` | map<string,string> | `{}` | `<canonical> → <IdP claim>`. |
| `.token_validation.clock_skew_seconds` | u64 | `60` | Leeway for `exp`, `nbf`, `iat`. |
| `.token_validation.cache_ttl_seconds` | u64 | `3600` | JWKS cache TTL. |
| `.allowed_redirect_uris` | list<string> | `[]` | Allow-list of `redirect_uri` values. Empty = only the synthesised default. |

## `security`

| Field | Type | Default | Description |
|---|---|---|---|
| `security.admin_token_env` | string | `""` | Env var name holding the admin token. |
| `security.require_admin_token` | bool | `true` | Refuse boot when `admin_token_env` is set but empty. |
| `security.cors_allowed_origins` | list<string> | `[]` | CORS origins. `["*"]` for wildcard; empty = no CORS layer. |
| `security.content_security_policy` | string | `"default-src 'none'; frame-ancestors 'none'"` | CSP header. Empty = skip. |
| `security.strict_transport_security` | string | `"max-age=63072000; includeSubDomains"` | HSTS header. Empty = skip. |
| `security.referrer_policy` | string | `"no-referrer"` | Referrer-Policy header. |
| `security.x_frame_options` | string | `"DENY"` | X-Frame-Options header. |
| `security.x_content_type_options` | string | `"nosniff"` | X-Content-Type-Options header. |

## Command-line + env

| Source | Purpose |
|---|---|
| `--config <path>` | Explicit config path. |
| `TIM_CONFIG` | Same, via env. |
| `RUST_LOG` | tracing_subscriber EnvFilter (`info`, `debug`, `tim=debug,sqlx=warn`). |

## Startup-refusal matrix

Startup fails hard when:

- `database.url_env` env var is unset.
- `security.require_admin_token: true` and `admin_token_env` is
  unset or its target env var is empty.
- `oauth2.session_store: "postgres"` and
  `session_encryption_key_env` is empty or the target env var is
  malformed hex / not 32 bytes.
- `oauth2.session_store` is anything other than `"memory"` or
  `"postgres"`.
- Any provider's `client_id_env` or `client_secret_env` target is
  unset.
- The JWT private key PEM is unreadable or not PKCS#8.
- Migrations fail (with `auto_migrate: true`).
