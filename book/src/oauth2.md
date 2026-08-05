# OAuth2 / OIDC

TIM proxies the standard OAuth2 authorization code flow to any
OIDC-compliant identity provider. Providers are configured in
`tim.yaml`; no code changes are needed to add a new one.

## Configuring a provider

Every provider is a block under `oauth2.providers.<id>`. See the
[configuration reference](./reference/config.md) for the full field
list.

Example — Google:

```yaml
server:
  # REQUIRED for the default callback URL to resolve outside
  # localhost. If empty, callers MUST pass ?redirect_uri= explicitly
  # AND it must be on the provider's allow-list.
  public_base_url: "https://tim.example.com"

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
      # Redirect-URI allow-list. First entry is the default when the
      # caller omits ?redirect_uri=; any caller-supplied value must
      # match one of the entries exactly.
      allowed_redirect_uris:
        - "https://tim.example.com/auth/callback/google"
        - "https://tim.example.com/auth/callback/google/staging"
```

At startup, TIM:

1. Reads the provider's discovery document from `discovery_url` (with
   retry-with-backoff on 5xx / network errors — three attempts).
2. Validates required fields (`issuer`, `authorization_endpoint`,
   `token_endpoint`, `jwks_uri`) plus, when advertised,
   `grant_types_supported` including `authorization_code` and
   `response_types_supported` including `code`.
3. Caches the discovery response for
   `oauth2.discovery_cache_ttl_seconds`.
4. Prepares an on-demand JWKS cache — JWKS is fetched at first
   ID-token verification and reused until
   `token_validation.cache_ttl_seconds` expires.
5. Resolves `client_id_env` and `client_secret_env` — refuses to
   start if either env var is unset.

## Authorization code flow

1. **`GET /auth/login/{provider_id}?redirect_uri=<...>`**

   TIM generates a random `state` + `nonce` (256 bits each),
   persists them to `auth.oauth_state`, and returns:

   ```json
   {
     "authorization_url": "https://accounts.google.com/o/oauth2/...&state=abc&nonce=def",
     "provider": "google",
     "state": "abc"
   }
   ```

   Consumer redirects the end-user to `authorization_url`.

   **`redirect_uri` resolution order:**
   1. Caller-supplied query param — accepted only if on the
      provider's `allowed_redirect_uris`.
   2. First entry of `allowed_redirect_uris` if that list is
      populated.
   3. Synthesised from `server.public_base_url` as
      `{public_base_url}/auth/callback/{provider_id}`.
   4. Error 400 if none of the above resolve.

2. **`GET /auth/callback/{provider_id}?code=<...>&state=<...>`**

   TIM:

   - Validates `state` (single-use — atomically `DELETE ...
     RETURNING`); rejects rows older than
     `oauth2.state_max_age_seconds` (default 300 s).
   - Exchanges `code` for tokens at the provider's `token_endpoint`.
   - **Verifies the ID token** — see next section.
   - Creates a session; expiry capped at
     `min(oauth2.session_ttl_seconds, expires_in-from-token-response)`.

   Response:

   ```json
   {
     "status": "ok",
     "provider": "google",
     "session_id": "abc123...",
     "expires_at": "2026-07-30T13:45:00Z",
     "user_profile": {
       "user_id": "user-google-000",
       "first_name": "Alice",
       "last_name": "Example",
       "email": "alice@example.com"
     }
   }
   ```

   If the IdP returned an `error=` (user cancelled, provider bounce),
   TIM bubbles the error as a structured 400 instead of a
   validation error:

   ```json
   {
     "status": "error",
     "provider": "google",
     "error": "access_denied",
     "error_description": "user cancelled"
   }
   ```

3. **`GET /auth/session/validate`** — session lookup + touch.
4. **`GET /auth/profile`** — canonical profile from the session.
5. **`POST /auth/logout`** — session invalidation.

Session-carrying endpoints accept three transports for the ID:

- `Authorization: Bearer sess_<id>` (recommended for new callers)
- `X-TIM-Session: <id>`
- `?session_id=<id>` — legacy, logged at debug level

See [Session storage](#session-storage) below.

## ID token verification

Every ID token returned by the token endpoint is validated per
OIDC Core §3.1.3.7 before the session is created. The verifier lives
in `src/oauth2/idtoken.rs`. It rejects the token if **any** of the
following fails:

1. Header parses; `alg` is a supported asymmetric algorithm
   (RS/PS/ES 256/384/512). `alg=none` and symmetric algorithms are
   refused outright.
2. `kid` (if present in the header) resolves to a key in the
   provider's JWKS. When absent, TIM falls back to the first JWKS
   key whose algorithm family matches the header.
3. Signature verifies against the resolved key.
4. `iss` claim matches `discovery.issuer` exactly.
5. `aud` claim contains the configured `client_id`.
6. `exp` > now (with `token_validation.clock_skew_seconds` leeway).
7. `nbf`, if present, ≤ now (with leeway).
8. `iat` ≤ now + leeway (future-date guard).
9. `nonce` MUST be present and MUST match the value TIM stored in
   `auth.oauth_state` at login time. Comparison is constant-time.

Failure → 422 Unprocessable Entity, no session created.

## Session storage

The session store is selected by `oauth2.session_store`. Two backends
are supported; anything else fails at startup.

### `session_store: "memory"` (default)

- In-process `DashMap`.
- Zero config.
- Sessions do NOT survive process restart.
- Sessions do NOT span replicas.
- Fine for single-replica dev and small deployments behind a
  session-affinity load balancer.

### `session_store: "postgres"`

- Persisted to `auth.session` (migration `0002_session_store.sql`).
- Profile data (which may contain PII from the IdP) is
  AEAD-encrypted at rest with chacha20poly1305.
- Required env var: name given by
  `oauth2.session_encryption_key_env` (default
  `TIM_SESSION_ENCRYPTION_KEY`), 64-hex-character value = 32 bytes.
- Survives restart; safe for multi-replica.
- Startup refuses if the encryption key env var is unset or
  malformed.

Both backends respect `oauth2.session_ttl_seconds` as an upper cap on
session lifetime — an oversized `expires_in` from the IdP does not
extend the session past this bound.

A background sweeper task, running every
`oauth2.session_sweep_interval_seconds` (default 60 s), deletes
expired sessions and orphaned `auth.oauth_state` rows. Set to 0 to
disable (test-only).

## TARA (Estonian eID)

TARA is a standard OIDC provider — the Rust integration is
config-only, same shape as Google or Azure. Test-environment and
production endpoints differ only in the discovery URL. Regression
coverage: `tests/it_oauth2_tara.rs` (7 cases).

Config:

```yaml
oauth2:
  providers:
    tara:
      name: "TARA"
      # Production. Test env: https://tara-test.ria.ee/oidc/.well-known/openid-configuration
      discovery_url: "https://tara.ria.ee/oidc/.well-known/openid-configuration"
      client_id_env: "TIM_TARA_CLIENT_ID"
      client_secret_env: "TIM_TARA_CLIENT_SECRET"
      scopes: ["openid"]     # add "phone", "idcard", "mid" to restrict method
      claim_mappings:
        # TARA emits the 11-digit personal code as the JWT `sub`
        # claim. Map into the profile as `personal_code` so
        # downstream services find it under a canonical name.
        personal_code: "sub"
        first_name: "given_name"
        last_name: "family_name"
        date_of_birth: "date_of_birth"
        acr: "acr"           # low / substantial / high
        amr: "amr"           # ["mID"] / ["smart-id"] / ["idcard"] / ["eIDAS"]
      token_validation:
        clock_skew_seconds: 60
        cache_ttl_seconds: 3600
      allowed_redirect_uris:
        - "https://tim.example.com/auth/callback/tara"
```

### Claim shape received from TARA

| Claim | Type | Purpose |
|---|---|---|
| `sub` | string (11 digits, e.g. `"60001019906"`) | Estonian personal code — legally-attested identity |
| `given_name` | string, UTF-8 | First name; Estonian characters (`Kärt`, `Ööbik`) preserved |
| `family_name` | string, UTF-8 | Family name |
| `date_of_birth` | string (`"YYYY-MM-DD"`) | Optional |
| `acr` | string | `"low"` / `"substantial"` / `"high"` — Level of Assurance |
| `amr` | array of strings | Authentication method used (`["mID"]`, `["smart-id"]`, `["idcard"]`, `["eIDAS"]`) |
| `profile_attributes` | object | Nested duplicate of some claims — NOT flattened by TIM; mapping is exact-key at the top level. |

### Scope semantics

TARA-specific scopes restrict which authentication methods the
user sees:

- `openid` alone — any method available on TARA (default).
- `openid phone` — Mobile-ID only.
- `openid idcard` — ID-card only.
- `openid mid` — synonym for Mobile-ID.

### Test vs prod

Swap `discovery_url` — nothing else changes:

- Test: `https://tara-test.ria.ee/oidc/.well-known/openid-configuration`.
- Prod: `https://tara.ria.ee/oidc/.well-known/openid-configuration`.

Client registration is separate per environment; test uses
`tara-test.ria.ee` client credentials, prod uses `tara.ria.ee`
ones.

### Level-of-Assurance policy enforcement

TIM extracts `acr` into the session profile but does **not**
enforce a minimum LoA. Downstream services that require a
`"high"`-LoA login (legal signature, sensitive personal data
retrieval) should check `user_profile.acr` themselves.

## PKCE

The current flow does NOT emit PKCE parameters. `auth.oauth_state`
has a `pkce_verifier` column reserved for a future PKCE
implementation. The `state` parameter alone provides CSRF
protection today; PKCE adds interception protection for public
clients, which TIM does not currently target. Some TARA / Google
client registrations may mandate PKCE — until PKCE is wired end
to end, such client registrations will reject TIM's login attempts
with `invalid_request`.

## Provider onboarding checklist

Adding a new provider:

1. Create OAuth2 credentials at the provider (client ID + secret).
2. Register your callback URLs — either
   `{server.public_base_url}/auth/callback/{provider_id}` or
   whatever you put in `allowed_redirect_uris`.
3. Add a block to `tim.yaml` under `oauth2.providers.<provider_id>`.
4. Set `<CLIENT_ID_ENV>` and `<CLIENT_SECRET_ENV>` in the environment.
5. Restart TIM. First `GET /auth/login/<provider_id>` triggers
   discovery + validation; watch for `discovery: provider does not
   advertise ...` errors in the log if the provider's advertisements
   are non-standard.
6. Test with `curl http://localhost:8085/auth/providers`.
