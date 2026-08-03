# 12 — Backlog doc references a `SessionStore` trait that does not exist

**Severity:** LOW (docs drift)
**Area:** Docs / architecture
**File:** `tasks/backlog/002-oauth2-session-store.md:32-45`

## What happens

The backlog task file for the Postgres session store claims:

> Replace `oauth2::session::MemoryStore` with `PostgresStore`. Trait
> already exists:
>
> ```rust
> pub trait SessionStore: Send + Sync {
>     async fn create(&self, session: Session) -> Result<()>;
>     ...
> }
> ```

There is no such trait. `grep -rn "trait SessionStore\|SessionStore:" src/`
returns nothing. `MemoryStore` is a concrete struct with inherent
methods; `AppState.sessions` is typed
`Arc<oauth2::session::MemoryStore>` at `src/router/mod.rs:34` — not
`Arc<dyn SessionStore>`. Introducing a Postgres implementation requires
either (a) creating the trait and refactoring every call site, or
(b) swapping the concrete type — neither of which the doc's "just add
a `PostgresStore` impl" framing captures.

## Impact

- Next engineer starts task 002, greps for `SessionStore`, finds
  nothing, wastes time reconciling the doc with the code.
- Filed as LOW because it's cosmetic, but this is the exact pattern
  that produces cargo-cult architectural drift.
