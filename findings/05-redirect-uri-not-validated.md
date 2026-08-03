# 05 — `redirect_uri` from client accepted without validation

**Severity:** MEDIUM (security posture)
**Area:** OAuth2 flow / router
**Files:**

- `src/router/mod.rs:247-260` (`auth_login`)
- `src/oauth2/flow.rs:33-80` (`build_login_url`)

## What happens

`GET /auth/login/{id}?redirect_uri=<any-url>` accepts an arbitrary
`redirect_uri` from the caller, sends it as-is to the IdP's
authorization endpoint, and stores it in `auth.oauth_state` for reuse
in the token exchange. There is:

- no allow-list of permitted redirect URIs per provider,
- no scheme check (http vs https),
- no host check,
- no length cap.

The last line of defence is the IdP itself: if the IdP is configured
to accept only registered redirect URIs, an attacker's attempt to
inject `redirect_uri=https://evil.com/x` will fail at the IdP. But TIM
itself trusts the input.

## Reference — Buerostack Java TIM

`OAuth2AuthenticationService.java:82` and
`OAuth2TokenService.java:63` both use the hard-coded
`http://localhost:8085/auth/callback/{providerId}` via `getCallbackUrl`.
The `clientRedirectUri` param is stored in `StateInfo` (line 60) but
never actually used in either the authorization request or the token
exchange. So Java is technically *safer* here (attacker can't influence
the URL), but only because the callback URL is hard-coded and there is
no way to run TIM behind a real reverse proxy in production without
changing code. Both are wrong; they're wrong differently.

## Impact

- Open-redirect surface. If a provider is misconfigured to allow
  wildcard or unregistered redirect URIs (some corporate IdPs do this),
  TIM will happily construct an authorization URL that lands the
  authorization code at `evil.com`.
- Provider-side rules become the only defence. A moment of provider
  misconfiguration = credential leak.

## Suggested direction

Config-driven allow-list per provider:

```yaml
oauth2:
  providers:
    google:
      allowed_redirect_uris:
        - "https://tim.example.com/auth/callback/google"
```

Reject any `redirect_uri` query param that is not on the list; default
to the first entry when omitted.
