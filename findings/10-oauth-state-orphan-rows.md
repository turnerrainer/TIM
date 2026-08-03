# 10 — `auth.oauth_state` rows are never garbage-collected

**Severity:** MEDIUM
**Area:** OAuth2 / database hygiene
**Files:**

- `src/oauth2/flow.rs:50-61` (INSERT on login)
- `src/oauth2/flow.rs:109-119` (DELETE ... RETURNING on successful callback)
- `migrations/0001_init.sql:71-82`

## What happens

`auth.oauth_state` rows are inserted on every `GET /auth/login/{id}`
call and deleted only when the user's browser hits
`GET /auth/callback/{id}` with a valid `code` + `state`. Every failure
path leaves the row behind:

- User closes the tab at the IdP → row lives forever.
- IdP returns an error (finding 04 rejects the request before delete).
- Callback deserialization fails (missing code or state) → 400 → row
  lives forever.
- Callback runs but token exchange throws (5xx) → row *is* deleted
  because the `DELETE ... RETURNING` fires first; but the state is
  now gone, so a legitimate retry with the same state is impossible.
  (Different problem, same table.)

There is no sweeper task, no TTL, no `WHERE created_at < now() -
interval '5 min'` cleanup. The `idx_auth_oauth_state_created` index
suggests one was intended but never wired up.

## Reference — Buerostack Java TIM

The Java `stateStorage` is an in-memory `ConcurrentHashMap`
(`OAuth2AuthenticationService.java:31`) with a 5-minute expiration
check at callback time (line 137). Java also *leaks* orphan entries
until process restart, so this is a mutual bug — but Java's leak is
bounded by process lifetime; Rust's leak is bounded by disk. Rust is
strictly worse for long-running deployments.

## Impact

- `auth.oauth_state` grows unbounded until manual cleanup.
- No integrity issue (state is single-use, non-secret, and can't be
  used to authenticate anything by itself), so this is HYGIENE not
  SECURITY. But it's the kind of table that eventually gets
  `DELETE FROM auth.oauth_state` run in an emergency and takes the
  database with it.
