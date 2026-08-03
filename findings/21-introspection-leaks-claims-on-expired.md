# 21 — `POST /introspect` returns full claim set for expired custom JWTs

**Severity:** LOW
**Area:** Introspection
**File:** `src/introspect/mod.rs:85-99`

## What happens

For expired-but-otherwise-valid custom JWTs, Rust responds:

```rust
if claims.exp < now {
    return Ok(IntrospectionResponse {
        active: false,
        iss: Some(claims.iss),
        sub: claims.sub,
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        jti: Some(claims.jti),
        aud: claims.aud,
        token_type: Some("custom_jwt".into()),
        extra_claims: claims.extra,
        ..Default::default()
    });
}
```

The `extra_claims` map contains any custom claims the token carried
(roles, tenant IDs, etc.). Same for `sub`, `aud`, `jti`.

## Reference — Buerostack Java TIM

`CustomJwtTokenValidator.introspect` at `.../CustomJwtTokenValidator.java:47-51`:

```java
if (jwt.getJWTClaimsSet().getExpirationTime().toInstant().isBefore(Instant.now())) {
    return IntrospectionResponse.inactive();
}
```

`inactive()` returns `{"active": false}` with all other fields null →
Jackson `@JsonInclude(NON_NULL)` at `IntrospectionResponse.java:10`
serializes bare `{"active": false}`.

## Impact

RFC 7662 §2.2 permits additional members when `active=false`, so this
is not a spec violation. But it is a behavioral change vs. JVM:

- A resource server that used introspection as a coarse "should I let
  this request through" check now sees claim data even for tokens it
  shouldn't act on.
- If the token contained PII in custom claims and someone posts the
  token to a shared introspection endpoint after expiry expecting it
  to be inert, PII is echoed back.

Note the divergence is **inconsistent** within the Rust file: signature
mismatch, unknown issuer, and jti-not-a-UUID all return bare
`{"active": false}` (`introspect/mod.rs:68-72, 79-83, 104-107`), while
expired and revoked paths return full claims. Pick one behavior.
