-- schema-security.sql — optional per-schema DB role isolation
-- (fixes audit finding 23).
--
-- NOT applied automatically by `sqlx::migrate!`. Run with a
-- superuser once, per deployment, if you want defense-in-depth
-- against a bug that accidentally crosses schema boundaries.
--
-- Roles created:
--   tim_custom_jwt     — RW on custom_jwt.*, no auth access
--   tim_auth           — RW on auth.*, no custom_jwt access
--   tim_introspect     — RO on both (used by an introspection-only
--                        read replica, if you run one)
--
-- Then update your deployment to run TIM with, e.g., three separate
-- database URLs and connect each subsystem via the narrowest role.
-- TIM itself does not fan out to three pools by default — this file
-- documents the *option*; operators who need the defence-in-depth
-- can wrap TIM behind a routing layer or use PgBouncer roles.

-- ONE-TIME: create roles + passwords via env before applying.
--   psql "$TIM_ADMIN_URL" \
--     -v tim_custom_jwt_password="$TIM_CJWT_PASSWORD" \
--     -v tim_auth_password="$TIM_AUTH_PASSWORD" \
--     -v tim_introspect_password="$TIM_INTROSPECT_PASSWORD" \
--     -f db/schema-security.sql
--
-- The `\gexec` pattern below skips CREATE USER if the role already
-- exists, keeping the script idempotent.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tim_custom_jwt') THEN
    EXECUTE format('CREATE USER tim_custom_jwt WITH PASSWORD %L',
                   current_setting('tim.cjwt_password', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tim_auth') THEN
    EXECUTE format('CREATE USER tim_auth WITH PASSWORD %L',
                   current_setting('tim.auth_password', true));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tim_introspect') THEN
    EXECUTE format('CREATE USER tim_introspect WITH PASSWORD %L',
                   current_setting('tim.introspect_password', true));
  END IF;
END $$;

-- Custom JWT role: RW on custom_jwt.*, no access to auth.
GRANT USAGE ON SCHEMA custom_jwt TO tim_custom_jwt;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA custom_jwt TO tim_custom_jwt;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA custom_jwt TO tim_custom_jwt;
REVOKE ALL ON SCHEMA auth FROM tim_custom_jwt;
ALTER DEFAULT PRIVILEGES IN SCHEMA custom_jwt
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tim_custom_jwt;

-- Auth role: RW on auth.*, no access to custom_jwt.
GRANT USAGE ON SCHEMA auth TO tim_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO tim_auth;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA auth TO tim_auth;
REVOKE ALL ON SCHEMA custom_jwt FROM tim_auth;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tim_auth;

-- Introspection role: RO on both schemas.
GRANT USAGE ON SCHEMA custom_jwt TO tim_introspect;
GRANT USAGE ON SCHEMA auth TO tim_introspect;
GRANT SELECT ON ALL TABLES IN SCHEMA custom_jwt TO tim_introspect;
GRANT SELECT ON ALL TABLES IN SCHEMA auth TO tim_introspect;
ALTER DEFAULT PRIVILEGES IN SCHEMA custom_jwt GRANT SELECT ON TABLES TO tim_introspect;
ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT SELECT ON TABLES TO tim_introspect;

-- Neither role can touch the public schema by default.
REVOKE ALL ON SCHEMA public FROM tim_custom_jwt;
REVOKE ALL ON SCHEMA public FROM tim_auth;
REVOKE ALL ON SCHEMA public FROM tim_introspect;
