//! Session storage. Trait + two implementations (memory + Postgres).
//!
//! Fixes findings 03 (config knob was ignored), 09 (TTL cap), 12
//! (backlog referenced a non-existent trait), 29 (touch was never
//! called).

pub mod crypto;
pub mod memory;
pub mod postgres;
mod store;

pub use crypto::SessionCipher;
pub use memory::MemoryStore;
pub use postgres::PostgresStore;
pub use store::{Session, SessionStore, SharedSessionStore};

/// Construct the store selected by config. Returns an
/// `Arc<dyn SessionStore>` so `AppState` can hold it uniformly.
pub async fn build(
    cfg: &crate::config::AppConfig,
    pool: sqlx::PgPool,
) -> crate::error::Result<SharedSessionStore> {
    let ttl = std::time::Duration::from_secs(cfg.oauth2.session_ttl_seconds);
    match cfg.oauth2.session_store.as_str() {
        "memory" => Ok(std::sync::Arc::new(MemoryStore::new(ttl))),
        "postgres" => {
            let key_hex = std::env::var(&cfg.oauth2.session_encryption_key_env).map_err(|_| {
                crate::error::TimError::Config(format!(
                    "oauth2.session_encryption_key_env `{}` is not set",
                    cfg.oauth2.session_encryption_key_env
                ))
            })?;
            let cipher = crypto::SessionCipher::from_hex_key(&key_hex)?;
            Ok(std::sync::Arc::new(PostgresStore::new(pool, ttl, cipher)))
        }
        other => Err(crate::error::TimError::Config(format!(
            "unknown session_store `{other}`"
        ))),
    }
}
