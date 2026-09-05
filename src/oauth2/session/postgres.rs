//! Postgres-backed session store. Fixes finding 03.
//!
//! Row layout is defined in migration `0002_session_store.sql`. The
//! `profile_encrypted` column holds an AEAD-sealed JSON blob so
//! session-carrying tokens are never at rest in plaintext.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use super::crypto::SessionCipher;
use super::store::{Session, SessionStore};
use crate::error::{Result, TimError};

pub struct PostgresStore {
    pool: PgPool,
    ttl: Duration,
    cipher: SessionCipher,
}

impl PostgresStore {
    pub fn new(pool: PgPool, ttl: Duration, cipher: SessionCipher) -> Self {
        Self { pool, ttl, cipher }
    }

    fn seal_profile(
        &self,
        profile: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(profile)
            .map_err(|e| TimError::Crypto(format!("profile serialise: {e}")))?;
        self.cipher.seal(&json)
    }

    fn open_profile(
        &self,
        sealed: &[u8],
    ) -> Result<std::collections::HashMap<String, serde_json::Value>> {
        let pt = self.cipher.open(sealed)?;
        serde_json::from_slice(&pt)
            .map_err(|e| TimError::Crypto(format!("profile deserialise: {e}")))
    }
}

#[async_trait]
impl SessionStore for PostgresStore {
    async fn create(&self, session: Session) -> Result<()> {
        let sealed = self.seal_profile(&session.profile)?;
        sqlx::query(
            r#"
            INSERT INTO auth.session
                (id, provider_id, user_id, created_at, last_activity,
                 expires_at, profile_encrypted)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&session.id)
        .bind(&session.provider_id)
        .bind(&session.user_id)
        .bind(session.created_at)
        .bind(session.last_activity)
        .bind(session.expires_at)
        .bind(sealed)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Session>> {
        // Fold the expiry check into the SELECT so `get()` is a single
        // query with no check-then-act race: a session that is expired
        // at query time returns `None` and expired rows are reaped by
        // the background sweeper (`sweep_expired`). Prior code did the
        // check in Rust and then issued an opportunistic DELETE — two
        // concurrent GETs could observe the same row as expired and
        // race the DELETE, producing inconsistent 404/401 pairs.
        type Row = (
            String,
            String,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
            DateTime<Utc>,
            Vec<u8>,
        );
        let row: Option<Row> = sqlx::query_as(
            r#"
            SELECT id, provider_id, user_id, created_at, last_activity, expires_at, profile_encrypted
              FROM auth.session
             WHERE id = $1
               AND expires_at > now()
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        let Some((id, provider_id, user_id, created_at, last_activity, expires_at, sealed)) = row
        else {
            return Ok(None);
        };
        let profile = self.open_profile(&sealed)?;
        Ok(Some(Session {
            id,
            provider_id,
            user_id,
            created_at,
            last_activity,
            expires_at,
            profile,
        }))
    }

    async fn touch(&self, id: &str) -> Result<()> {
        let _ = sqlx::query(
            r#"
            UPDATE auth.session
               SET last_activity = now()
             WHERE id = $1
               AND expires_at > now()
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn revoke(&self, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM auth.session WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn sweep_expired(&self) -> Result<u64> {
        let res = sqlx::query("DELETE FROM auth.session WHERE expires_at <= now()")
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    fn ttl_cap(&self) -> Duration {
        self.ttl
    }
}
