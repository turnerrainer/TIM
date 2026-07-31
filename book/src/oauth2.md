# OAuth2 / OIDC

TIM proxies the standard OAuth2 authorization code flow to any
OIDC-compliant identity provider. Providers are configured in
`tim.yaml`; no code changes are needed to add a new one.

## Configuring a provider

Every provider is a block under `oauth2.providers.<id>`. See the
[configuration chapter](./configuration.md) for the full field
reference.

Example — Google:

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
```

At startup, TIM:

1. Reads the provider's discovery document from `discovery_url`.
2. Caches the discovery response for `oauth2.discovery_cache_ttl_seconds`.
3. Fetches and caches the provider's JWKS from `jwks_uri`.
4. Resolves `client_id_env` and `client_secret_env` — refuses to
   start if either env var is unset.

## Authorization code flow

1. **`GET /auth/login/{provider_id}?redirect_uri=<...>`**

   TIM generates a random `state` + `nonce`, persists them to
   `auth.oauth_state`, and returns:

   ```json
   {
     "authorization_url": "https://accounts.google.com/o/oauth2/...&state=abc&nonce=def",
     "provider": "google",
     "state": "abc"
   }
   ```

   Consumer redirects the end-user to `authorization_url`.

2. **`GET /auth/callback/{provider_id}?code=<...>&state=<...>`**

   TIM:

   - Validates `state` (single-use — DELETE from `auth.oauth_state`).
   - Exchanges `code` for tokens at the provider's `token_endpoint`.
   - Validates the ID token: signature (via cached JWKS), `iss`
     matches the discovery `issuer`, `aud` matches configured
     `client_id`, `exp > now()`, `nonce` matches persisted value.
   - Creates a session.

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

3. **`GET /auth/session/validate?session_id=<...>`** — session lookup.
4. **`GET /auth/profile?session_id=<...>`** — canonical profile from
   the session's ID token claims (using `claim_mappings`).
5. **`POST /auth/logout?session_id=<...>&reason=<...>`** — session
   invalidation.

## Session storage — MVP limitation

The 0.1.0-alpha.1 session store is **in-process** (a `DashMap`). This
means:

- Sessions do NOT survive process restart.
- Sessions do NOT span replicas.

**Consequence**: run TIM as a single replica behind a session-affinity
load balancer until [task 002](https://github.com/turnerrainer/tim/blob/dev/tasks/backlog/002-oauth2-session-store.md)
lands (Postgres-backed session store with encrypted-at-rest token
material).

TIM logs a `WARN` at startup when `oauth2.session_store: "memory"`
is in effect so this constraint is visible in operator logs.

## PKCE

The 0.1.0-alpha.1 flow does NOT emit PKCE parameters. `auth.oauth_state`
has a `pkce_verifier` column reserved for [task 003](https://github.com/turnerrainer/tim/blob/dev/tasks/backlog/003-pkce-flow.md).
The `state` parameter alone provides CSRF protection today; PKCE
adds interception protection for public clients, which TIM does not
currently target.

## Provider onboarding checklist

Adding a new provider:

1. Create OAuth2 credentials at the provider (client ID + secret).
2. Register `<TIM_HOST>/auth/callback/<provider_id>` as an allowed
   redirect URI.
3. Add a block to `tim.yaml` under `oauth2.providers.<provider_id>`.
4. Set `<CLIENT_ID_ENV>` and `<CLIENT_SECRET_ENV>` in the environment.
5. Restart TIM. Check the log for `Loaded OIDC discovery for
   provider=<id>` — success. If missing, check `discovery_url`.
6. Test with `curl http://localhost:8085/auth/providers`.
