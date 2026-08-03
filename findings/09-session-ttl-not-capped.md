# 09 — Session TTL is not capped to the configured maximum

**Severity:** MEDIUM (security posture)
**Area:** OAuth2 session lifetime
**Files:**

- `src/oauth2/flow.rs:177-190` (`complete_callback` expiry math)
- `src/config/mod.rs:76-77` + `234-236` (`session_ttl_seconds`, default 86400)

## What happens

```rust
let expires_at =
    now + Duration::seconds(tokens.expires_in.unwrap_or(sessions.ttl().as_secs() as i64));
```

The session expiry is `expires_in` from the IdP token response,
falling back to the configured TTL only when `expires_in` is absent.
An IdP that returns a large `expires_in` (e.g., a 30-day access token
lifetime) produces a TIM session that lives for 30 days regardless of
the operator's `session_ttl_seconds: 86400` setting.

## Reference — Buerostack Java TIM

`SessionManagementService.createSession` at
`.../oauth2/service/SessionManagementService.java:43-51`:

```java
Instant sessionExpiry = Instant.now().plus(24, ChronoUnit.HOURS);
if (tokenResponse.getExpiresIn() != null) {
    Instant tokenExpiry = Instant.now().plus(tokenResponse.getExpiresIn(), ChronoUnit.SECONDS);
    if (tokenExpiry.isBefore(sessionExpiry)) {
        sessionExpiry = tokenExpiry;
    }
}
```

Java takes `min(configured_ttl, token_ttl)`. Rust takes
`token_ttl or configured_ttl`. The Rust behavior can extend a session
past the operator-configured cap; the Java behavior can shorten it, but
never extend it past 24h.

## Impact

- Operators set `session_ttl_seconds: 86400` believing sessions cap
  at 24h. They do not.
- Long-lived provider access tokens (some corporate SSO deployments
  hand out tokens with `expires_in` in the millions of seconds) yield
  practically-immortal TIM sessions.

## Root-cause note

This is the "trace the full call chain" pattern from the audit-cycle
lessons in `CLAUDE.md`. The `session_ttl_seconds` config knob exists,
the `MemoryStore::ttl` field is populated correctly, but the *reader*
at the seam only consults it as a fallback. A grep-based check for
"is ttl enforced" would have caught this.
