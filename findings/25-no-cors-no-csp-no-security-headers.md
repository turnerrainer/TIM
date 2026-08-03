# 25 — No CORS, CSP, HSTS, or other security-response middleware

**Severity:** MEDIUM
**Area:** HTTP security
**Files:**

- `src/router/mod.rs:37-68` — only `DefaultBodyLimit`, `TimeoutLayer`,
  `TraceLayer`. No `CorsLayer`, no `SetResponseHeaderLayer`.
- No `tower-http = { ... features = ["cors", ...] }` in `Cargo.toml`.

## What happens

Every HTTP response leaves TIM naked: no `Content-Security-Policy`,
no `Strict-Transport-Security`, no `X-Content-Type-Options: nosniff`,
no `Referrer-Policy`, no CORS handling, no `X-Frame-Options`. Anything
in front of TIM (reverse proxy) is expected to add these.

## Reference

- **Buerostack Java TIM**: same behavior (`SecurityConfig.java` only
  disables CSRF + permit-all). Parity preserved with the JVM 2.0
  parent.
- **Original Buerokratt TIM**:
  `SecurityConfiguration.java:65-67, 152-160` configures CORS from
  `cors.allowedOrigins` and sets `contentSecurityPolicy` from a
  configurable string. Rust regresses vs. the original.

## Impact

- Assumes an operator will always run TIM behind a hardened proxy.
  In the demo `docker-compose.yml`, TIM is exposed directly on
  `0.0.0.0:8085`.
- Browser-facing callers cannot preflight CORS without help from a
  proxy — `Access-Control-Allow-Origin` is never sent.
- Not a security *vulnerability* per se; a security *posture gap*
  vs. what the original TIM shipped.
