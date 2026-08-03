# 24 — DB pool tuning is minimal — no acquire timeout, no idle timeout

**Severity:** LOW
**Area:** Database
**Files:**

- `src/db/mod.rs:7-15`
- `src/config/mod.rs:32-42`

## What happens

```rust
PgPoolOptions::new()
    .min_connections(cfg.min_connections)
    .max_connections(cfg.max_connections)
    .connect(url)
    .await
```

Only `min_connections` (default 2) and `max_connections` (default 10)
are set. No `acquire_timeout` (defaults to 30s in sqlx 0.8; unbounded
in some earlier versions), no `idle_timeout`, no `max_lifetime`, no
`test_before_acquire`. Under a Postgres restart or PgBouncer
reconnect, stale connections in the pool will fail on first use.

## Reference — Buerostack Java TIM

Spring Boot's Hikari default: `connection-timeout=30s`,
`max-lifetime=30 min`, `idle-timeout=10 min`,
`connection-test-query=SELECT 1`. Rust starts with fewer defaults and
no way for operators to tune them without a code change.

## Impact

- Long uptimes without connection recycling risk stale connections
  eventually failing requests until pool refresh.
- Not a security issue; filed as operational parity.
