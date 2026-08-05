use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub provider_id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub profile: HashMap<String, serde_json::Value>,
}

impl Session {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

/// Backing store for OAuth2 sessions. Every method is fallible so
/// Postgres transport errors surface to the caller rather than being
/// swallowed.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    async fn create(&self, session: Session) -> Result<()>;
    async fn get(&self, id: &str) -> Result<Option<Session>>;
    /// Update `last_activity` to now. Silent no-op if the session is
    /// unknown or already expired (finding 29).
    async fn touch(&self, id: &str) -> Result<()>;
    /// Returns true if a row existed and was removed.
    async fn revoke(&self, id: &str) -> Result<bool>;
    /// Called by the background sweeper. Returns number of rows GC'd.
    async fn sweep_expired(&self) -> Result<u64>;
    /// Configured TTL — used to *cap* the session expiry against
    /// caller-supplied `expires_in` (finding 09).
    fn ttl_cap(&self) -> Duration;
}

pub type SharedSessionStore = Arc<dyn SessionStore>;
