-- 0001 — Initial TIM schema.
--
-- Two logical schemas: custom_jwt (TIM-issued RS256 tokens) and
-- auth (OAuth2/OIDC state + planned session tables).
--
-- Every table INSERT-only where possible; revocation goes to
-- denylist rows, not UPDATEs. This preserves an immutable audit
-- trail of every token TIM ever issued.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE SCHEMA IF NOT EXISTS custom_jwt;
CREATE SCHEMA IF NOT EXISTS auth;

-- ---------------------------------------------------------------
-- custom_jwt.jwt_metadata
--
-- One row per generated custom JWT. Extension chains are
-- reconstructed via original_jwt_uuid + supersedes.
-- ---------------------------------------------------------------
CREATE TABLE custom_jwt.jwt_metadata (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    jwt_uuid            uuid NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    claim_keys          text NOT NULL,
    issued_at           timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    subject             text,
    jwt_name            text,
    audience            text,
    issuer              text,
    supersedes          uuid,
    original_jwt_uuid   uuid NOT NULL
);

CREATE INDEX idx_custom_jwt_metadata_subject
    ON custom_jwt.jwt_metadata (subject);
CREATE INDEX idx_custom_jwt_metadata_issued
    ON custom_jwt.jwt_metadata (issued_at);
CREATE INDEX idx_custom_jwt_metadata_jwt_uuid
    ON custom_jwt.jwt_metadata (jwt_uuid, created_at DESC);
CREATE INDEX idx_custom_jwt_metadata_original
    ON custom_jwt.jwt_metadata (original_jwt_uuid);

-- ---------------------------------------------------------------
-- custom_jwt.denylist
--
-- Revoked JWT jti values. Checked on every validate call.
-- expires_at exists so a background sweeper can purge rows past
-- the token's original expiration (they are no longer needed —
-- the token would fail validation on exp anyway).
-- ---------------------------------------------------------------
CREATE TABLE custom_jwt.denylist (
    jwt_uuid            uuid PRIMARY KEY,
    created_at          timestamptz NOT NULL DEFAULT now(),
    denylisted_at       timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    reason              text
);

CREATE INDEX idx_custom_jwt_denylist_exp
    ON custom_jwt.denylist (expires_at);

-- ---------------------------------------------------------------
-- auth.oauth_state
--
-- Persisted CSRF state + nonce + PKCE verifier for the OAuth2
-- authorization code flow. Rows are single-use and DELETED on
-- callback consumption.
-- ---------------------------------------------------------------
CREATE TABLE auth.oauth_state (
    state               text PRIMARY KEY,
    created_at          timestamptz NOT NULL DEFAULT now(),
    provider_id         text NOT NULL,
    nonce               text NOT NULL,
    pkce_verifier       text,
    redirect_uri        text
);

CREATE INDEX idx_auth_oauth_state_created
    ON auth.oauth_state (created_at);
