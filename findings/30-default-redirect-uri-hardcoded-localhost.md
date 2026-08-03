# 30 — Default `redirect_uri` is `http://localhost:{server.port}/...`

**Severity:** LOW (production-hostile default)
**Area:** OAuth2 flow / router
**File:** `src/router/mod.rs:252-257`

## What happens

If the caller omits `redirect_uri`, TIM synthesises
`http://localhost:{server.port}/auth/callback/{id}` and sends *that*
to the IdP. In production TIM is typically behind a proxy on port 443
under a real hostname (e.g. `https://tim.example.com`), and the IdP
will 302 the browser to `http://localhost:...` which is meaningless to
the end user's machine.

## Reference — Buerostack Java TIM

`OAuth2AuthenticationService.getCallbackUrl` at
`.../OAuth2AuthenticationService.java:98-101` and
`OAuth2TokenService.getCallbackUrl` at
`.../OAuth2TokenService.java:103-106` — both hard-code the same
`http://localhost:8085/auth/callback/{providerId}` with a `// TODO:
Make this configurable` comment. Rust inherited the TODO without
fixing it.

## Impact

- Any deployment that does not pass `redirect_uri` explicitly on
  every `/auth/login/{id}` call gets a broken flow.
- No config field like `oauth2.public_base_url` exists to fix this
  properly.

## Suggested direction

Add `oauth2.public_base_url: "https://tim.example.com"` to
`AppConfig::oauth2` and use it as the default. Reject deployments
where `public_base_url` is unset AND `server.bind` is `0.0.0.0`
(non-loopback bind implies non-localhost callers).
