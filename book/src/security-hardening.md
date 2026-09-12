# Security hardening

TIM ships secure defaults, but its threat model changes with the
deployment topology. This chapter walks through every knob that
affects the security posture: what the default is, what the safer
production setting looks like, and what breaks if you get it wrong.

## Admin token

**Config:** `security.admin_token_env` (default
`"TIM_ADMIN_TOKEN"`), `security.require_admin_token` (default
`true`).

**Gated endpoints:**

- `POST /jwt/custom/generate`
- `POST /jwt/custom/revoke`
- `POST /jwt/custom/revoke/bulk`
- `POST /jwt/custom/extend`
- `POST /jwt/custom-jwt-blacklist` (legacy)
- `POST /jwt/blacklist` (legacy)

**Transport:** callers present the token via one of:

- `X-TIM-Admin-Token: <secret>` (preferred)
- `Authorization: Bearer <secret>` (accepted for symmetry with modern
  APIs; use only when the caller is not simultaneously carrying a
  user JWT)

Comparison is constant-time (`subtle::ConstantTimeEq`).

**Provisioning:**

```bash
# 32 random bytes, hex-encoded — 64 chars. Store in your secrets
# manager alongside the DB password.
openssl rand -hex 32
```

Mount into the container's environment via docker-compose / k8s
secret / whatever your platform does. TIM refuses to boot if
`require_admin_token: true` (the default) and the referenced env
var is unset or empty.

**Ungated mode** (`require_admin_token: false` + empty
`admin_token_env`): available only for tests and single-machine dev.
Startup logs a WARN. Never deploy this way to a network reachable by
untrusted callers.

## HTTP response headers

**Config:** `security.content_security_policy`,
`security.strict_transport_security`, `security.referrer_policy`,
`security.x_frame_options`, `security.x_content_type_options`.

Each is a string that becomes a response header on every route
(including 404s). Empty string skips a given header.

Defaults are conservative — the shipped `tim.yaml` sets:

```yaml
content_security_policy: "default-src 'none'; frame-ancestors 'none'"
strict_transport_security: "max-age=63072000; includeSubDomains"
referrer_policy: "no-referrer"
x_frame_options: "DENY"
x_content_type_options: "nosniff"
```

These are TIM's own responses. If your reverse proxy already sets
these headers, either leave TIM's alone (harmless — the proxy
usually preserves) or set the fields to `""` to opt out.

## CORS

**Config:** `security.cors_allowed_origins` (default `[]`).

Behaviour:

- `[]` (default) — no CORS layer, no `Access-Control-*` headers
  emitted. Same-origin callers work; cross-origin browser callers
  get blocked at the browser.
- `["*"]` — wildcard `Access-Control-Allow-Origin: *`; browser
  callers from anywhere accepted; credentials NOT allowed
  (browser-side spec restriction with wildcard).
- Explicit list — reflected origin match plus
  `Access-Control-Allow-Credentials: true` for cookie-carrying
  browsers. Recommended in production.

Example:

```yaml
security:
  cors_allowed_origins:
    - "https://app.example.com"
    - "https://admin.example.com"
```

## Session encryption at rest

**Config:** `oauth2.session_store: "postgres"` +
`oauth2.session_encryption_key_env` (default
`"TIM_SESSION_ENCRYPTION_KEY"`).

When `postgres` is selected, the profile map in `auth.session` is
sealed with chacha20poly1305 (12-byte random nonce prepended to the
ciphertext + tag). A 32-byte (64 hex chars) key is required; startup
refuses if the env var is unset or malformed.

Generate and mount:

```bash
openssl rand -hex 32
```

**Key rotation:** out-of-scope for the current release — rotating
the key invalidates all existing sessions. Plan a rollout that
drains sessions before rotating, or accept the forced re-login.

## Database schema isolation (optional)

**File:** `db/schema-security.sql` (NOT auto-applied).

By default, TIM runs against a single Postgres role with full access
to both `custom_jwt.*` and `auth.*`. For defense-in-depth against a
bug that accidentally crosses schema boundaries, apply
`db/schema-security.sql` as a superuser once per deployment:

```bash
psql "$TIM_ADMIN_URL" \
  -v tim.cjwt_password="$TIM_CJWT_PASSWORD" \
  -v tim.auth_password="$TIM_AUTH_PASSWORD" \
  -v tim.introspect_password="$TIM_INTROSPECT_PASSWORD" \
  -f db/schema-security.sql
```

Then run three TIM instances (or one TIM behind a routing layer /
PgBouncer) each connecting as the narrowest role:

- **`tim_custom_jwt`** — RW on `custom_jwt.*`, no `auth` access.
- **`tim_auth`** — RW on `auth.*`, no `custom_jwt` access.
- **`tim_introspect`** — RO on both.

A bug that queries the wrong schema now raises `permission denied`
at the DB rather than silently succeeding. Not required for
correctness — offered for operators who want the extra layer.

## Key rotation

The JWT signing key is loaded once at startup from a PKCS#8 PEM file
(`jwt.private_key_path`). To rotate:

1. Generate a new PKCS#8 PEM keypair.
2. Update `jwt.key_id` to a new value.
3. Deploy a new TIM instance with the new key + new kid.
4. Verify `/jwt/keys/public` on the new instance advertises the new
   kid.
5. Drain traffic from the old instance.

The old kid disappears from JWKS immediately on cutover. Downstream
services that cache JWKS with a TTL keep validating old-kid tokens
until their cache expires. Size the overlap window accordingly.

There is no runtime rotation endpoint. This is deliberate — see the
"What TIM does NOT do" note in the [Introduction](./introduction.md).

## Container posture

The shipped Dockerfile + docker-compose.yml enforce:

- Non-root user (`useradd -m -u 1000 tim`).
- Read-only root filesystem (`read_only: true`), tmpfs for `/tmp`.
- All Linux capabilities dropped (`cap_drop: [ALL]`).
- `no-new-privileges` set.
- Resource limits (CPU / memory) applied.
- Tini as init to reap zombies.
- Healthcheck on `/health` every 30 s.

If you build your own image, keep these guarantees. If you run TIM
outside Docker (systemd, Nomad), replicate the equivalent primitives.

## Rate limiting

TIM does not rate-limit. Put a rate-limiting reverse proxy in
front: nginx `limit_req`, envoy `local_ratelimit`, cloud WAF, etc.
The admin-gated endpoints are the primary abuse targets; validate
and userinfo are relatively cheap but still worth capping.

## Pre-boot validation — `tim doctor`

Every deploy should run `tim doctor` before restarting the service.
The subcommand parses `tim.yaml`, resolves every referenced env var
(admin token, database URL, session encryption key, provider
credentials, introspection client secrets), verifies the JWT key
file exists and parses as PKCS#8 PEM, and prints a structured
PASS / WARN / FAIL table. It never binds a port, never opens a
Postgres connection, never touches the network — safe to run in
locked-down CI.

```console
$ tim doctor
[  OK  ] config: loaded from /etc/tim/tim.yaml
[  OK  ] config: validate: all cross-field checks pass
[  OK  ] jwt.private_key: parsed OK from /etc/secrets/tim/jwt-private.pem (kid=prod-2026-01)
[  OK  ] database.url_env: `TIM_DATABASE_URL` resolved to a non-empty value
[  OK  ] security.admin_token_env: `TIM_ADMIN_TOKEN` resolved (require_admin_token = true)
[  OK  ] introspection.clients: client[ruuter].client_secret_env `TIM_INTROSPECT_RUUTER_SECRET` resolved
[ WARN ] jwt.audience: validation_enabled = false — every caller can request any audience.
---
Summary: 6 pass, 1 warn, 0 fail (total 7)
```

Exit codes: `0` on all-pass (WARN advisory), `1` on any FAIL or
(under `--strict`) any WARN, `2` on doctor itself failing. Wire
into deploy pipelines as a pre-flight gate:

```bash
tim doctor --strict || { echo "config unsafe, refusing deploy"; exit 1; }
```

## Offline mode — `TIM_OFFLINE=1`

For pentest engagements, adversarial CI, or any environment where
TIM must NOT accidentally reach a real upstream IdP: set
`TIM_OFFLINE=1` and every outbound HTTP call (discovery, JWKS,
token exchange) refuses with 502 instead of hitting the network.
Boot emits a WARN so operators see the flag in the log. Env-only
knob, snapshotted at first read; changing it mid-run has no
effect.

## W3C Trace Context — every response carries `traceparent`

TIM emits `traceparent: 00-<32-hex trace-id>-<16-hex span-id>-<2-hex flags>`
and `x-trace-id: <32-hex trace-id>` on every response, including
4xx and 5xx. When a request arrives with a well-formed incoming
`traceparent` (typically from Ruuter, the fleet reverse proxy),
TIM echoes the caller's trace-id and preserves their sampling
decision (flags). Span-id is always fresh — TIM is a new span
within the (possibly-inherited) trace.

Downstream tooling can correlate a specific TIM response with
TIM's log line by grepping the trace-id; the access-log line that
names the request carries the same value:

```
INFO http_request_completed method=POST route=/introspect
     status=200 duration_us=1234 trace_id=<same 32-hex value>
```

## Strict request schemas — `#[serde(deny_unknown_fields)]`

Every modern JSON body / form / query DTO carries
`#[serde(deny_unknown_fields)]`. A caller sending
`{"token":"x","admin_override":true}` gets 4xx with the offending
field named, instead of the extra field being silently dropped.
Applies to:

- `POST /jwt/custom/{generate,validate,extend,revoke,revoke/bulk,list/me}`
- `POST /introspect` (both JSON and form-encoded)
- `POST /auth/logout` (body), `GET /auth/login/:id` (query)

Deliberately exempt (compat / IdP-driven surfaces): JVM 1.x compat
endpoints, `GET /auth/callback/:id` (IdPs add per-request params
per RFC 6749), and IdP response DTOs (discovery, JWKS, token
response).

## Threat model summary

| Attacker capability | Protection |
|---|---|
| Reach the network | Admin gate on state-changing endpoints (26); reverse-proxy rate limits; CORS if browser-borne |
| Steal a session ID | Session IDs travel via header (27); still short-lived (`session_ttl_seconds` cap, 9) |
| Steal an admin token | Constant-time compare (26); short-token lifetime by rotation; monitor for unusual `X-TIM-Admin-Token` traffic |
| Compromise the IdP token endpoint | ID-token JWKS signature verification (01); `iss` / `aud` / `nonce` (02) blocks forged tokens |
| Compromise the DB | Session profile encrypted at rest; JWT tokens hashed to jti in denylist (no plaintext in DB) |
| Bug in JWT service that touches auth schema | Optional per-schema role isolation (23) |
| Downgrade to `alg=none` | Refused at token-header parse (see `oauth2::idtoken::verify`) |
