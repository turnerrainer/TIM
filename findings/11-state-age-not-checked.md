# 11 — `auth.oauth_state` age is not checked at callback

**Severity:** MEDIUM (security posture)
**Area:** OAuth2 flow
**File:** `src/oauth2/flow.rs:109-127`

## What happens

Callback consumes state via `DELETE ... RETURNING`. Age is not
inspected — a state row created hours ago is accepted as readily as
one created seconds ago. Only the caller having the exact 256-bit
`state` value protects against replay, but a state that leaks (server
log capture, browser history sync, referer bleed) remains usable for
weeks until the row is manually purged (see finding 10).

## Reference — Buerostack Java TIM

`OAuth2AuthenticationService.validateCallback` at
`.../oauth2/service/OAuth2AuthenticationService.java:136-140`:

```java
if (System.currentTimeMillis() - stateInfo.getTimestamp() > 300_000) {
    return new CallbackValidation(false, "State parameter expired", ...);
}
```

Java caps state age at 5 minutes. Rust: unbounded.

## Impact

- Extends the window during which a captured `state` value can be
  used to complete an authorization flow initiated by the victim.
- Compounds with finding 10 (rows never cleaned up), because the
  row remains INSERT-only until callback consumption.

## Root-cause note

Trivial to fix: add
`AND created_at > now() - interval '5 minutes'` to the DELETE
WHERE clause. The `created_at` column exists (`migrations/0001_init.sql:73`).
The `idx_auth_oauth_state_created` index was clearly created for this
purpose, then abandoned.
