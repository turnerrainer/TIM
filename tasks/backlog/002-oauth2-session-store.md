# 002 — Postgres-backed OAuth2 session store

## Filed

2026-07-30 — MVP ships with in-process `DashMap` session storage
(see STANDARDS.md §Project-specific extras). This blocks multi-pod
deployments — sessions do not survive process restart, do not span
replicas. Documented in the book but flagged as a known limitation
for the RC.

## Severity

Medium. Blocks HA deployments. Single-replica deployments and
development are unaffected. Not a security hole — the session ID
is high-entropy and unguessable; the risk is availability +
correctness across replicas, not disclosure.

## Motivation

Sessions live in `oauth2::session::Store` today, backed by
`DashMap<SessionId, Session>`. Restart the process → every session
is gone → every user gets logged out. Deploy two replicas behind a
non-affinity load balancer → users bounce between replicas and see
"session expired" randomly.

The Java TIM has the same limitation (documented in its README),
so the Rust rewrite starts at parity, not regression. But the whole
point of the standards is to fix the JVM bugs we're carrying, not
just reproduce them.

## Fix / Design

Replace `oauth2::session::MemoryStore` with `PostgresStore`. Trait
already exists:

```rust
pub trait SessionStore: Send + Sync {
    async fn create(&self, session: Session) -> Result<()>;
    async fn get(&self, id: &SessionId) -> Result<Option<Session>>;
    async fn touch(&self, id: &SessionId) -> Result<()>;
    async fn revoke(&self, id: &SessionId) -> Result<()>;
    async fn sweep_expired(&self) -> Result<u64>;
}
```

Schema addition (new migration):

```sql
CREATE TABLE auth.session (
  id text PRIMARY KEY,
  provider_id text NOT NULL,
  user_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_activity timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  status text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  tokens_encrypted bytea NOT NULL,        -- AEAD-encrypted TokenData
  authentication_method text,
  level_of_assurance text
);

CREATE INDEX idx_auth_session_expires ON auth.session (expires_at);
CREATE INDEX idx_auth_session_user ON auth.session (user_id, provider_id);
```

Token material MUST be encrypted at rest — `tokens_encrypted` holds
an AEAD ciphertext (chacha20poly1305) using a key derived from the
same KMS mount as the JWT signing key (new config field
`oauth2.session_encryption_key_path`).

Config change:

```yaml
oauth2:
  session_store: "postgres"    # was "memory"
  session_encryption_key_path: "/opt/tim/keys/session-enc.key"
```

Background sweeper task deletes rows where `expires_at < now()`
every 60 s.

## Acceptance

- [ ] Migration `0002_session_store.sql` adds `auth.session`.
- [ ] `PostgresStore` impl of `SessionStore` in `oauth2::session::pg`.
- [ ] Token material encrypted with chacha20poly1305 before persist;
      decrypted on read.
- [ ] Background sweeper task started from `main.rs`; interval
      configurable via `oauth2.session_sweep_interval_seconds`.
- [ ] Integration test: create session in replica A, look it up
      in replica B (parallel `PgPool`s targeting same DB).
- [ ] STANDARDS.md updated: remove §Project-specific extras entry
      about in-process sessions.
- [ ] `book/src/oauth2.md` updated: session persistence section
      rewritten from "MVP limitation" to "how it works."

## Estimated effort

2 days.

## Dependencies

None. Independent of task 003 (PKCE) and task 004 (metrics).

## Non-scope

- Session replication protocol (Postgres IS the replication).
- Redis backing store (Postgres is sufficient for TIM's session
  volume; adding Redis is scope creep).

## Risks

- Encryption key rotation is out of scope for this task; document
  as a separate follow-up.
- Session sweeper may lock rows under high concurrency — use
  `DELETE FROM ... WHERE expires_at < now() LIMIT 1000` batched
  loop with sleep.
