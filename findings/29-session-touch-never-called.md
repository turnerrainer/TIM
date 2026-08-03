# 29 — `MemoryStore::touch` is never invoked; `last_activity` is frozen

**Severity:** LOW
**Area:** OAuth2 session
**Files:**

- `src/oauth2/session.rs:58-62` — `touch(&self, id: &str)` defined
- No call sites — `grep -n "\.touch(" src/` returns nothing.
- `src/router/mod.rs:297` — `/auth/session/validate` returns
  `last_activity` but does not update it.

## What happens

`Session.last_activity` is set at session creation time
(`flow.rs:186`) and never advanced. `GET /auth/session/validate` and
`GET /auth/profile` both check `is_expired(now)` but do not call
`touch()`. The `last_activity` field returned by
`/auth/session/validate` is therefore always equal to `created_at`.

## Reference — Buerostack Java TIM

`SessionManagementService.validateSession` at
`.../SessionManagementService.java:120`:

```java
session.setLastActivity(Instant.now());
```

Fires on every successful validation.

## Impact

- Any UI that shows "last activity" or uses it for idle-timeout
  displays the login time forever. Not exploitable, but wrong.
- Filed as LOW because there's no code path that uses `last_activity`
  for authorization decisions. If any future code adds an idle-timeout
  policy keyed on `last_activity`, sessions will time out after
  `session_ttl` from *creation*, not from *last use*.
