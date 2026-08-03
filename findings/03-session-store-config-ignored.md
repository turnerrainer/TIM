# 03 — `oauth2.session_store` config key is silently ignored

**Severity:** HIGH (correctness / operations)
**Area:** OAuth2 session persistence
**Files:**

- `src/main.rs:39-44` (warning branch)
- `src/main.rs:88-91` (`oauth2_session_store`)
- `src/config/mod.rs:70-80` (config surface)
- `tim.yaml:53-58` (documented option)

## What happens

The config surface advertises a `session_store` string (default
`"memory"`). `main.rs` warns only if the value is `"memory"` — but the
constructor `oauth2_session_store` always returns a `MemoryStore`
regardless of the configured value:

```rust
fn oauth2_session_store(config: &AppConfig) -> tim::oauth2::session::MemoryStore {
    let ttl = std::time::Duration::from_secs(config.oauth2.session_ttl_seconds);
    tim::oauth2::session::MemoryStore::new(ttl)
}
```

Setting `session_store: "postgres"` (or anything else) in `tim.yaml`
produces **no error**, **no warning**, and **no behavior change**. The
operator believes they've enabled a persistent store; TIM still stores
sessions in a `DashMap`. This is the exact pattern that got flagged in
the audit-cycle lessons — "verifying a fix in isolation against a
mental model, instead of tracing actual data flow."

## Reference — Buerostack Java TIM

Same in-memory approach in `SessionManagementService.java:28` — but the
Java version doesn't advertise a knob it doesn't honour.

## Impact

- Operators believe their sessions are durable; they are not.
- Every `TIM` restart invalidates every session (users get logged out).
- Multi-replica deployments break silently: a session created on
  replica A is unknown to replica B, so `/auth/session/validate`,
  `/auth/profile`, `/auth/logout` all fail non-deterministically.
- `HANDOFF.md` and `tim.yaml` both describe this as "MVP" while the
  crate published as `tim` version `0.1.0-alpha.1` claims full JVM
  parity in commit `d4c27c3`. The parity claim is inaccurate.
