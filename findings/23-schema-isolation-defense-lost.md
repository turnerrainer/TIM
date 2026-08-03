# 23 — Schema-level DB permission isolation lost

**Severity:** MEDIUM (defense-in-depth regression)
**Area:** Database
**Files:**

- `src/db/mod.rs:7-15` (single PgPool)
- `migrations/0001_init.sql:12-13` (`CREATE SCHEMA` but no GRANT/USER)
- `docker-compose.yml:9-10` (single `POSTGRES_USER: tim`)
- Reference: `/home/rainer/Desktop/Buerostack/TIM/db/schema-security.sql`

## What happens

The Rust rewrite runs against a single Postgres role (`tim`) with full
access to both `custom_jwt.*` and `auth.*` tables. There is one
`PgPool`, one URL, one credential set.

## Reference — Buerostack Java TIM

`db/schema-security.sql` creates three dedicated roles with narrow
per-schema grants:

```sql
CREATE USER tim_custom_jwt WITH PASSWORD '...';
CREATE USER tim_auth WITH PASSWORD '...';
CREATE USER tim_introspect WITH PASSWORD '...';

GRANT USAGE ON SCHEMA custom_jwt TO tim_custom_jwt;
REVOKE ALL ON SCHEMA auth FROM tim_custom_jwt;
-- etc.
```

`DatabaseConfig.java:20-113` wires three separate JPA datasources
(`customJwtDataSource`, `authDataSource`, `primaryDataSource`) each
using a different role, plus `SchemaIsolationAspect.java` for
service-layer access logging.

The design intent (see JVM readme + the schema-security file itself):
if a bug in the JWT service accidentally references `auth.oauth_state`,
the DB rejects the statement — the credential doesn't have USAGE on
the auth schema.

## Impact

- Loss of defense-in-depth. A query bug in `jwt::service` that
  accidentally reads or writes `auth.oauth_state` will succeed
  silently on Rust, but would raise `permission denied for schema
  auth` on JVM.
- The comment in `migrations/0001_init.sql:3-4` ("Two logical schemas")
  reads as an intent-preserving nod without any of the enforcement.
- The `tim_introspect` read-only role for the introspection service
  is not present. Compromise of the introspect endpoint gives full
  write access to both schemas.

## Suggested direction

Add a follow-up migration that creates dedicated roles + grants (or
document explicitly that Rust chose to trade this off for
single-pool simplicity — but the trade-off should be visible in
STANDARDS.md, not silent).
