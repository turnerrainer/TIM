# 26 — `POST /jwt/custom/generate` is unauthenticated and unrestricted

**Severity:** HIGH (deployment-dependent)
**Area:** Authentication
**File:** `src/router/mod.rs:44` (route table)

## What happens

Anyone who can reach TIM can mint a signed JWT with any `sub`, any
custom claims, any audience, and up to `max_claims_bytes` of payload.
There is no bearer requirement, no basic auth, no IP allow-list, no
API key. The `/jwt/custom/generate` route is publicly callable.

## Reference

- **Original Buerokratt TIM**:
  `SecurityConfiguration.java:80-83` restricts three
  privileged endpoints (`/jwt/custom-jwt-generate`,
  `/jwt/custom-jwt-userinfo`, `/jwt/change-jwt-role`) via
  `.access(getAllowedIps())` — the caller must come from an IP on
  `security.allowlist.jwt`.
- **Buerostack Java TIM**: dropped the IP allow-list in the 2.x
  rewrite (`SecurityConfig.java:12-17` — `.anyRequest().permitAll()`).
  Rust inherits the JVM 2.0 posture, not the original.

## Impact

If TIM is exposed on any network that untrusted clients can reach,
those clients can:

1. Mint a JWT for `sub: "admin"`, `role: "superuser"`, `aud: "any"`.
2. Present that JWT to any downstream service that trusts TIM's
   `iss: "TIM"` — the signature verifies (because TIM signed it),
   the exp is in the future, the denylist is empty, so introspection
   returns `active: true`.

The only defence is network topology. In the current
`docker-compose.yml` (`ports: - "8085:8085"`) TIM is exposed on all
container-host interfaces. `curl -X POST
http://localhost:8085/jwt/custom/generate -H 'content-type:
application/json' -d '{"JWTName":"x","content":{"sub":"admin"},"expirationInMinutes":60}'`
gives a valid admin token to anyone with shell access to the host.

## Suggested direction

At minimum, require an operator-configured static key (bearer or
`X-TIM-Auth`) on `/jwt/custom/*` and `/introspect`. IP allow-list is
also cheap. Document the assumption if the design is "always deploy
behind an authenticated proxy" — the demo compose doesn't demonstrate
that pattern.
