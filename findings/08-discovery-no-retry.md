# 08 — OIDC discovery fetch has no retry policy

**Severity:** LOW
**Area:** OAuth2 discovery
**File:** `src/oauth2/discovery.rs:42-66`

## What happens

Discovery fetch is a single reqwest `.get(...).send().await`. Any
transient failure (5xx, connection reset, DNS blip) surfaces to the
caller as `502 Bad Gateway` and no future login attempt for that
provider proceeds until the caller retries.

## Reference — Buerostack Java TIM

`OidcDiscoveryService.discoverProvider` at
`.../oauth2/service/OidcDiscoveryService.java:47-49`:

```java
.retryWhen(Retry.backoff(3, Duration.ofSeconds(1))
        .maxBackoff(Duration.ofSeconds(10)))
```

Three retries with exponential backoff up to 10s.

## Impact

- User-perceived reliability lower than JVM version during upstream
  brownouts.
- Not a security issue; not a spec violation. Filed for parity.
