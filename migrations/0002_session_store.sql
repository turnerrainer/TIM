-- 0002 — Postgres-backed OAuth2 session store (finding 03).
--
-- Rows are INSERT-only until sweep — `last_activity` is UPDATE'd on
-- validate. `profile_encrypted` holds a chacha20poly1305 blob so
-- profile data (which may contain PII from the IdP) is never at rest
-- in plaintext.

CREATE TABLE auth.session (
    id                  text PRIMARY KEY,
    provider_id         text NOT NULL,
    user_id             text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_activity       timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    profile_encrypted   bytea NOT NULL
);

CREATE INDEX idx_auth_session_expires
    ON auth.session (expires_at);
CREATE INDEX idx_auth_session_user
    ON auth.session (user_id, provider_id);
