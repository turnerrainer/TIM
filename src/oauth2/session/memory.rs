use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;

use super::store::{Session, SessionStore};
use crate::error::Result;

/// In-process session store — for single-replica deployments and
/// tests. Multi-replica production must use `PostgresStore`.
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
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn create(&self, session: Session) -> Result<()> {
        self.map.insert(session.id.clone(), session);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Session>> {
        let now = Utc::now();
        let entry = match self.map.get(id) {
            Some(e) => e,
            None => return Ok(None),
        };
        if entry.is_expired(now) {
            drop(entry);
            self.map.remove(id);
            return Ok(None);
        }
        Ok(Some(entry.clone()))
    }

    async fn touch(&self, id: &str) -> Result<()> {
        if let Some(mut entry) = self.map.get_mut(id) {
            entry.last_activity = Utc::now();
        }
        Ok(())
    }

    async fn revoke(&self, id: &str) -> Result<bool> {
        Ok(self.map.remove(id).is_some())
    }

    async fn sweep_expired(&self) -> Result<u64> {
        let now = Utc::now();
        let expired: Vec<String> = self
            .map
            .iter()
            .filter(|e| e.value().is_expired(now))
            .map(|e| e.key().clone())
            .collect();
        let n = expired.len() as u64;
        for id in expired {
            self.map.remove(&id);
        }
        Ok(n)
    }

    fn ttl_cap(&self) -> Duration {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

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

    #[tokio::test]
    async fn create_and_get_round_trip() {
        let store = MemoryStore::new(Duration::from_secs(60));
        store.create(fresh_session("s1", 60)).await.unwrap();
        assert!(store.get("s1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn expired_session_is_gc_on_get() {
        let store = MemoryStore::new(Duration::from_secs(60));
        store.create(fresh_session("s1", -10)).await.unwrap();
        assert!(store.get("s1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_returns_true_when_present() {
        let store = MemoryStore::new(Duration::from_secs(60));
        store.create(fresh_session("s1", 60)).await.unwrap();
        assert!(store.revoke("s1").await.unwrap());
        assert!(!store.revoke("s1").await.unwrap());
    }

    #[tokio::test]
    async fn touch_updates_last_activity() {
        let store = MemoryStore::new(Duration::from_secs(60));
        let s = fresh_session("s1", 60);
        let created = s.last_activity;
        store.create(s).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        store.touch("s1").await.unwrap();
        let read = store.get("s1").await.unwrap().unwrap();
        assert!(read.last_activity > created);
    }

    #[tokio::test]
    async fn sweep_removes_expired_only() {
        let store = MemoryStore::new(Duration::from_secs(60));
        store.create(fresh_session("keep", 60)).await.unwrap();
        store.create(fresh_session("gone", -1)).await.unwrap();
        let n = store.sweep_expired().await.unwrap();
        assert_eq!(n, 1);
        assert!(store.get("keep").await.unwrap().is_some());
        assert!(store.get("gone").await.unwrap().is_none());
    }
}
