# 22 — `POST /introspect` returns 415 on missing/unknown Content-Type

**Severity:** LOW (RFC 7662 §2.1 nuance)
**Area:** Introspection
**File:** `src/router/mod.rs:182-208`

## What happens

Handler inspects the `Content-Type` header manually:

```rust
if ct.starts_with("application/json") { ... }
else if ct.starts_with("application/x-www-form-urlencoded") { ... }
else { return Err(TimError::UnsupportedMediaType); }
```

Missing Content-Type → 415. Non-form, non-JSON → 415.

## Reference — RFC 7662 §2.1

The introspection request "uses the `application/x-www-form-urlencoded`
format" — clients SHOULD send it. But the RFC does not mandate a hard
rejection with 415; historically most implementations accept any
Content-Type and attempt to parse as form-urlencoded.

## Reference — Buerostack Java TIM

Two `@PostMapping` handlers with `consumes = ...`; Spring returns 415
when neither matches. Same behavior as Rust — parity preserved.

## Impact

- `curl -X POST /introspect --data 'token=xyz'` without setting
  `-H 'Content-Type: application/x-www-form-urlencoded'` (curl does
  set it by default for `--data`, but rusty callers with hand-crafted
  HTTP clients may not) returns 415 instead of a useful answer.
- Filed as LOW; behavior matches JVM. Called out for future ergonomics
  work.
