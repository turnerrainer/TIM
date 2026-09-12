# Configuration

TIM loads its config from a YAML file. Search order at startup:

1. `--config <path>` CLI flag.
2. `TIM_CONFIG=<path>` env var.
3. `./tim.yaml` or `./tim.yml` in the working directory.
4. Built-in defaults (equivalent to the shipped `tim.yaml`).

Every field has a safe default; override only what you need.
Passwords and secrets are **never** in the config file itself — the
config points at an env-var name, and startup refuses if that env
var is missing when the referring section is configured.

This page is a walk-through. For a flat, alphabetised reference,
see [Configuration reference](./reference/config.md).

## Sections

TIM's config has five top-level sections:

- `server` — HTTP listener, request limits, public base URL.
- `database` — Postgres URL env var + pool tuning.
- `jwt` — signing key, issuer, audience validation, legacy cookie
  name.
- `oauth2` — provider registry, session store, discovery cache,
  sweeper.
- `security` — admin token, CORS, response headers.

## `server`

```yaml
server:
  bind: "0.0.0.0"
  port: 8085
  max_request_bytes: 1048576
  request_timeout_seconds: 30
  public_base_url: "https://tim.example.com"
```

The default `bind: "0.0.0.0"` is container-friendly; for local dev
outside a container use `127.0.0.1`.

`public_base_url` is used to synthesise the default OAuth2 callback
URL. Startup logs a WARN if empty AND `bind != "127.0.0.1"` because
that combination usually means "TIM is reachable from outside
localhost but doesn't know its own address."

## `database`

```yaml
database:
  url_env: "TIM_DATABASE_URL"
  min_connections: 2
  max_connections: 10
  auto_migrate: true
  acquire_timeout_seconds: 30
  idle_timeout_seconds: 600
  max_lifetime_seconds: 1800
```

`url_env` is the *name* of the env var that holds the actual
`postgres://` URL. Startup refuses if that env var is unset.

Pool knobs correspond one-to-one with sqlx's `PgPoolOptions`
methods. Setting a value to `0` skips calling the corresponding
`.acquire_timeout()` / `.idle_timeout()` / `.max_lifetime()` (i.e.,
uses sqlx's own default).

`auto_migrate: true` runs the SQL in `migrations/` on every boot.
Set `false` when your CI already applied them.

## `jwt`

```yaml
jwt:
  private_key_path: "/opt/tim/keys/jwt-private.pem"
  key_id: "tim-rs-1"
  issuer: "TIM"
  audience:
    validation_enabled: false
    allowed: []
    default: "tim-service"
  max_claims_bytes: 32768
  bulk_revoke_max: 100
  cookie_name: "jwt"
```

`private_key_path` points at a PKCS#8 PEM file; the public half is
derived and served at `/jwt/keys/public`. Rotation is redeploy-only
— see [Security hardening](./security-hardening.md#key-rotation).

`audience.validation_enabled: true` makes TIM reject
`POST /jwt/custom/generate` requests whose `audience` is not in
`audience.allowed`. Off by default.

`cookie_name` is used only by the [legacy compatibility
endpoints](./legacy-compat.md); it must match the name your DSL /
browser client uses.

## `oauth2`

```yaml
oauth2:
  session_store: "memory"     # or "postgres"
  discovery_cache_ttl_seconds: 3600
  session_ttl_seconds: 86400
  session_sweep_interval_seconds: 60
  state_max_age_seconds: 300
  session_encryption_key_env: "TIM_SESSION_ENCRYPTION_KEY"
  providers: {}
```

**`session_store`** — `"memory"` for single-replica dev,
`"postgres"` for production. Anything else fails at startup.

**`session_ttl_seconds`** — hard cap on session lifetime; the
effective expiry is `min(this, expires_in-from-IdP)`. See
[OAuth2 / OIDC](./oauth2.md#session-storage).

**`state_max_age_seconds`** — how long an `auth.oauth_state` row
remains eligible for callback consumption. 5 min is standard.

**`session_sweep_interval_seconds`** — background task that deletes
expired sessions + stale state rows. 0 disables (tests only).

**`session_encryption_key_env`** — required when
`session_store: "postgres"`. Name of the env var holding a 32-byte
key hex-encoded (64 chars). Startup refuses if unset in postgres
mode.

### `oauth2.providers.<id>`

```yaml
oauth2:
  providers:
    google:
      name: "Google"
      discovery_url: "https://accounts.google.com/.well-known/openid-configuration"
      client_id_env: "TIM_GOOGLE_CLIENT_ID"
      client_secret_env: "TIM_GOOGLE_CLIENT_SECRET"
      scopes: ["openid", "profile", "email"]
      claim_mappings:
        first_name: "given_name"
        last_name: "family_name"
        email: "email"
      token_validation:
        clock_skew_seconds: 60
        cache_ttl_seconds: 3600
      allowed_redirect_uris:
        - "https://tim.example.com/auth/callback/google"
```

**`claim_mappings`** are `<canonical name> → <IdP claim name>` —
what gets extracted into the session's profile map. If the ID token
has `given_name: "Alice"`, `first_name: "given_name"` in the map
puts `first_name: "Alice"` on the session.

**`token_validation.clock_skew_seconds`** is real leeway applied to
`exp`, `nbf`, and `iat` during ID-token verification.

**`allowed_redirect_uris`** — see [`redirect_uri` resolution in the
OAuth2 chapter](./oauth2.md#authorization-code-flow). Empty list =
only the synthesised `{public_base_url}/auth/callback/{id}` is
accepted; explicit list = caller-supplied URI must be an exact
match; missing caller URI = first entry used as default.

## `security`

```yaml
security:
  admin_token_env: "TIM_ADMIN_TOKEN"
  require_admin_token: true
  cors_allowed_origins: []
  content_security_policy: "default-src 'none'; frame-ancestors 'none'"
  strict_transport_security: "max-age=63072000; includeSubDomains"
  referrer_policy: "no-referrer"
  x_frame_options: "DENY"
  x_content_type_options: "nosniff"
```

See [Security hardening](./security-hardening.md) for every field.

`require_admin_token: true` is the default and enforced at startup;
setting to `false` and leaving `admin_token_env: ""` is a valid but
noisy combination (WARN in the log; **do not deploy to production
this way**).

## `introspection`

RFC 7662 §2.1 recommends that `POST /introspect` require client
authentication. **As of 0.4.0-alpha the gate is on by default**
(audit FN1) — a config that does not set `introspection.clients`
refuses to start. Register every legitimate downstream caller:

```yaml
introspection:
  required_client_auth: true      # default in 0.4.0-alpha
  clients:
    - client_id: "ruuter-classifier"
      client_secret_env: "TIM_INTROSPECT_RUUTER_SECRET"
    - client_id: "analytics-worker"
      client_secret_env: "TIM_INTROSPECT_ANALYTICS_SECRET"
```

Callers present `Authorization: Basic <base64(id:secret)>` on every
request. Scheme name is case-insensitive per RFC 7235 §2.1 —
`Basic`, `basic`, `BASIC` all take the same path. Missing header,
unknown id, wrong secret → 401. Secret comparison is constant-time
(`subtle::ConstantTimeEq`). Startup fails if any referenced
`client_secret_env` is unset while the gate is on.

To opt out (dev, one-off scripts, running behind a proxy that
authenticates the caller already):

```yaml
introspection:
  required_client_auth: false
```

Boot then emits a WARN naming the risk. Any deployment that reaches
the public internet SHOULD keep the gate on.

### Extending the gate to `/jwt/custom/validate*` (audit F-TIM-2)

`/jwt/custom/validate` and `/jwt/custom/validate/boolean` have the
same DoS shape as `/introspect` (crypto verify → denylist SELECT)
but ship without an auth gate by default — every internal service
that TIM issued a token for calls them constantly, so requiring
Basic auth is BC-breaking for existing callers.

For deployments where TIM is exposed to untrusted networks OR where
the reverse proxy in front can forward a Basic header from its
guards, opt in:

```yaml
introspection:
  gate_validation_endpoints: true
  # Same clients: list as above — one gate, one secret rotation.
```

With the gate on, an unauthenticated `POST /jwt/custom/validate`
returns 401 BEFORE the DB SELECT + crypto verify run — so an
attacker cannot drive the DB pool to exhaustion.

### Extending the gate to JVM 1.x compat validation endpoints (audit F-TIM-6)

Same shape for `/jwt/userinfo`, `/jwt/custom-jwt-verify`,
`/jwt/custom-jwt-userinfo`. These require a cookie present, but
the cookie value is not authenticated — any value drives a
crypto-verify + DB SELECT.

Enabling the gate breaks browser-direct DSL flows unless the
reverse proxy forwards a Basic header on behalf of the browser:

```yaml
introspection:
  gate_jvm_compat_endpoints: true
```

The three gates (`required_client_auth`, `gate_validation_endpoints`,
`gate_jvm_compat_endpoints`) are independent — enable exactly the
subset your topology permits.

## Environment variables

Every value TIM reads at runtime is one of:

- A field in `tim.yaml`.
- An env var named by an `_env`-suffixed field in `tim.yaml`.
- `RUST_LOG` — standard `tracing_subscriber::EnvFilter` syntax
  (`info`, `debug`, `tim=debug,sqlx=warn`).
- `TIM_CONFIG` — path to the config file (alternative to `--config`).
- `TIM_OFFLINE` — see below.

There are no undocumented env vars.

Required env vars in a typical production deployment:

| Env var name | Purpose |
|---|---|
| `TIM_DATABASE_URL` | Postgres connection URL. |
| `TIM_ADMIN_TOKEN` | Admin token for privileged endpoints. |
| `TIM_SESSION_ENCRYPTION_KEY` | Only when `session_store: "postgres"`. |
| `TIM_<PROVIDER>_CLIENT_ID`, `_CLIENT_SECRET` | One pair per OAuth2 provider. |
| `TIM_INTROSPECT_<CALLER>_SECRET` | One per introspection client (see above). |

### `TIM_OFFLINE` — pentest / break-test gate

Set `TIM_OFFLINE=1` (or `true`, `yes`) to make every outbound HTTP
call refuse with 502 instead of hitting the network. Intended for
pentest engagements, adversarial CI, and any environment where TIM
must NOT accidentally reach a real upstream IdP:

- OIDC discovery (`GET .well-known/openid-configuration`)
- JWKS fetch (`GET jwks_uri`)
- Token exchange (`POST token_endpoint`)

Boot emits a WARN naming the flag so operators see the posture in
the log stream. Value is snapshotted at first read; changing it
mid-run has no effect. Not a config field — env-only so a CI job
doesn't have to touch operator `tim.yaml`.

## Sample production overrides

```yaml
server:
  public_base_url: "https://tim.example.com"

database:
  url_env: "TIM_DATABASE_URL"
  min_connections: 5
  max_connections: 25
  auto_migrate: false        # run migrations from CI instead

jwt:
  private_key_path: "/etc/secrets/tim/jwt-private.pem"
  key_id: "prod-2026-01"
  cookie_name: "jwt"

oauth2:
  session_store: "postgres"
  session_ttl_seconds: 3600  # tighter than default 24h
  providers:
    google:
      name: "Google"
      discovery_url: "https://accounts.google.com/.well-known/openid-configuration"
      client_id_env: "TIM_GOOGLE_CLIENT_ID"
      client_secret_env: "TIM_GOOGLE_CLIENT_SECRET"
      scopes: ["openid", "profile", "email"]
      allowed_redirect_uris:
        - "https://tim.example.com/auth/callback/google"

security:
  admin_token_env: "TIM_ADMIN_TOKEN"
  require_admin_token: true
  cors_allowed_origins:
    - "https://app.example.com"
```

Env at deploy:

```bash
TIM_DATABASE_URL=postgres://tim:$(vault kv get -field=password secret/tim/db)@db:5432/tim
TIM_ADMIN_TOKEN=$(vault kv get -field=token secret/tim/admin)
TIM_SESSION_ENCRYPTION_KEY=$(vault kv get -field=key secret/tim/session)
TIM_GOOGLE_CLIENT_ID=<from Google Cloud Console>
TIM_GOOGLE_CLIENT_SECRET=<from Google Cloud Console>
```
