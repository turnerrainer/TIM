# 17 — `token_type` claim not injected into signed JWT

**Severity:** LOW (parity gap; introspection extensibility break)
**Area:** Custom JWT / Introspection
**Files:**

- `src/jwt/service.rs:53-126` (`generate`) — no `token_type` written
- `src/introspect/mod.rs:75-83` (routes by `iss` == config.issuer only)

## What happens

The Rust `generate` never writes a `token_type` claim into the JWT
body. Introspection routes solely by comparing `claims.iss` to
`config.issuer`.

## Reference — Buerostack Java TIM

`CustomJwtService.generate` at `.../custom-jwt/.../service/CustomJwtService.java:23-27`:

```java
Map<String,Object> claimsWithType = new HashMap<>(claims);
claimsWithType.put("token_type", "custom_jwt");
String token = signer.sign(claimsWithType, ...);
```

`TokenIntrospectionService.extractTokenType` at
`.../server/.../introspection/service/TokenIntrospectionService.java:79-124`
routes by `token_type` claim with a fallback heuristic on `iss` +
`aud == "tim-audience"`.

## Impact

- The Java version's dispatcher pattern (register additional
  `TokenValidator` implementations keyed by `token_type`) can't be
  replicated without changing every issued token. Task 005 (external
  JWKS introspection) will need to invent a different routing key
  when it lands.
- Tokens issued today are indistinguishable from any other RS256
  token issued by TIM on the introspection wire. The response includes
  `token_type: "custom_jwt"` regardless — the *type is asserted, not
  derived*.
- Downstream services that inspect the raw JWT (not via TIM's
  introspect endpoint) lose a claim they had in JVM.

## Correctness note

Neither behavior is strictly wrong per RFC 7519 — `token_type` is
non-standard on either side. But if the JVM version is the reference,
the parity gap is real.
