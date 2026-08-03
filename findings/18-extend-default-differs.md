# 18 — `POST /jwt/custom/extend` default TTL differs

**Severity:** LOW (behavior parity)
**Area:** Custom JWT
**File:** `src/jwt/service.rs:368-370`

## What happens

```rust
let exp_minutes = req
    .expiration_in_minutes
    .unwrap_or_else(|| (old.exp - old.iat) / 60);
```

When `expirationInMinutes` is omitted, Rust extends by *the original
token's lifetime*. Java extends by a fixed 60 minutes:

```java
Integer expirationMinutes = request.getExpirationInMinutes() != null ?
    request.getExpirationInMinutes() : 60;
```

(`.../custom-jwt/.../api/CustomJwtController.java:241-242`)

## Impact

- Client that omits `expirationInMinutes` and relied on the JVM's 60-min
  default now gets a different TTL — potentially a much longer one
  (30-day tokens now extend by 30 days each call), potentially a much
  shorter one (1-minute tokens extend by 1 minute).
- Not exploitable, but observable and undocumented in the changelog.
