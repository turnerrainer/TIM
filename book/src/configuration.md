# Configuration

TIM loads its config from a YAML file. Search order at startup:

1. `--config <path>` CLI flag.
2. `TIM_CONFIG=<path>` env var.
3. `./tim.yaml` or `./tim.yml` in the working directory.
4. Built-in defaults (equivalent to the shipped `tim.yaml`).

Every field has a safe default; override only what you need.
Passwords and secrets are **never** in the config file itself —
the config points at an env var name, and startup refuses if that
env var is missing when the referring section is configured.

## `tim.yaml` field reference

### `server`

| Field | Default | Purpose |
|---|---|---|
| `bind` | `"0.0.0.0"` | Bind address. `127.0.0.1` for local-only. |
| `port` | `8085` | Listening port. |
| `max_request_bytes` | `1048576` (1 MB) | Global request body cap. |
| `request_timeout_seconds` | `30` | Per-request deadline. Overruns → 408. |

### `database`

| Field | Default | Purpose |
|---|---|---|
| `url_env` | `"TIM_DATABASE_URL"` | Name of env var holding the Postgres URL. Startup refuses if the referenced env var is unset. |
| `min_connections` | `2` | Pool floor. |
| `max_connections` | `10` | Pool ceiling. |
| `auto_migrate` | `true` | Run migrations at startup. Set `false` if migrations are managed externally. |

The URL format is standard `postgres://user:pass@host:port/dbname`.

### `jwt`

| Field | Default | Purpose |
|---|---|---|
| `private_key_path` | `"/opt/tim/keys/jwt-private.pem"` | PKCS#8 PEM RSA private key. Loaded once at startup. |
| `key_id` | `"tim-rs-1"` | `kid` advertised in JWS headers + JWKS. |
| `issuer` | `"TIM"` | `iss` claim on every issued token. |
| `audience.validation_enabled` | `false` | If true, reject tokens whose `aud` is not in `allowed`. |
| `audience.allowed` | `[]` | Allow-list when validation is enabled. |
| `audience.default` | `"tim-service"` | Fallback `aud` if the caller does not provide one. |
| `max_claims_bytes` | `32768` | Cap on custom claim payload size at generate time. |
| `bulk_revoke_max` | `100` | Max tokens per `/jwt/custom/revoke/bulk` call. |

### `oauth2`

| Field | Default | Purpose |
|---|---|---|
| `session_store` | `"memory"` | `"memory"` (in-process DashMap) or `"postgres"` (post-MVP; see task 002). |
| `discovery_cache_ttl_seconds` | `3600` | OIDC discovery document + JWKS cache TTL per provider. |
| `providers` | `{}` | Map of provider ID → provider config. See [OAuth2 chapter](./oauth2.md). |

Each entry under `providers.<id>` has:

| Field | Purpose |
|---|---|
| `name` | Human-readable label. |
| `discovery_url` | OIDC `.well-known/openid-configuration` URL. |
| `client_id_env` | Env var holding the client ID. |
| `client_secret_env` | Env var holding the client secret. |
| `scopes` | List of scopes to request (default `["openid","profile","email"]`). |
| `claim_mappings` | Map of canonical field → provider claim name. |
| `token_validation.clock_skew_seconds` | Tolerance for `exp` / `nbf` checks. Default 60. |
| `token_validation.cache_ttl_seconds` | Cached-validation TTL. Default 3600. |

## Environment variables

Every value TIM reads at runtime is one of:

- A field in `tim.yaml`.
- An env var named by a `_env` field in `tim.yaml`.
- `RUST_LOG` — standard `tracing_subscriber::EnvFilter` syntax
  (`info`, `debug`, `tim=debug,sqlx=warn`).

There are no undocumented env vars.

## Sample overrides

Minimum production override — set the DB URL, point at your mounted
key, and configure one OAuth2 provider:

```yaml
database:
  url_env: "TIM_DATABASE_URL"

jwt:
  private_key_path: "/etc/secrets/tim/jwt-private.pem"
  key_id: "prod-2026-01"

oauth2:
  providers:
    google:
      name: "Google"
      discovery_url: "https://accounts.google.com/.well-known/openid-configuration"
      client_id_env: "TIM_GOOGLE_CLIENT_ID"
      client_secret_env: "TIM_GOOGLE_CLIENT_SECRET"
      scopes: ["openid", "profile", "email"]
```

Then set the env at deploy:

```bash
TIM_DATABASE_URL=postgres://tim:$(vault kv get -field=password secret/tim/db)@db:5432/tim
TIM_GOOGLE_CLIENT_ID=<from Google Cloud Console>
TIM_GOOGLE_CLIENT_SECRET=<from Google Cloud Console>
```
