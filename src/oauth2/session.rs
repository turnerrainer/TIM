use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

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

/// In-process session store. See STANDARDS.md §Project-specific
/// extras — this is an MVP; multi-replica deployments need the
/// Postgres-backed variant (backlog task 002).
pub struct MemoryStore {
    map: Arc<DashMap<String, Session>>,
    ttl: Duration,
}

impl MemoryStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: Arc::new(DashMap::new()),
            ttl,
        }
    }

    pub fn create(&self, session: Session) {
        self.map.insert(session.id.clone(), session);
    }

    pub fn get(&self, id: &str) -> Option<Session> {
        let now = Utc::now();
        let entry = self.map.get(id)?;
        if entry.is_expired(now) {
            drop(entry);
            self.map.remove(id);
            return None;
        }
        Some(entry.clone())
    }

    pub fn touch(&self, id: &str) {
        if let Some(mut entry) = self.map.get_mut(id) {
            entry.last_activity = Utc::now();
        }
    }

    pub fn revoke(&self, id: &str) -> bool {
        self.map.remove(id).is_some()
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_session(id: &str, ttl_seconds: i64) -> Session {
        let now = Utc::now();
        Session {
            id: id.into(),
            provider_id: "p".into(),
            user_id: "u".into(),
            created_at: now,
            last_activity: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds),
            profile: HashMap::new(),
        }
    }

    #[test]
    fn create_and_get_round_trip() {
        let store = MemoryStore::new(Duration::from_secs(60));
        store.create(fresh_session("s1", 60));
        assert!(store.get("s1").is_some());
    }

    #[test]
    fn expired_session_is_gc_on_get() {
        let store = MemoryStore::new(Duration::from_secs(60));
        store.create(fresh_session("s1", -10));
        assert!(store.get("s1").is_none());
    }

    #[test]
    fn revoke_returns_true_when_present() {
        let store = MemoryStore::new(Duration::from_secs(60));
        store.create(fresh_session("s1", 60));
        assert!(store.revoke("s1"));
        assert!(!store.revoke("s1"));
    }
}
