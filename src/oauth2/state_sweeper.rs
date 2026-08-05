//! Background sweeper for expired sessions + stale `auth.oauth_state`
//! rows. Fixes findings 10 (orphan state rows) and, combined with
//! `PostgresStore::sweep_expired`, keeps session storage from growing
//! unbounded.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::config::OAuth2Config;
use crate::oauth2::session::SharedSessionStore;

/// Spawn the sweeper as a detached tokio task. `interval_seconds = 0`
/// disables the loop (used by tests).
pub fn spawn(cfg: &OAuth2Config, pool: PgPool, sessions: SharedSessionStore) {
    let interval_seconds = cfg.session_sweep_interval_seconds;
    let state_max_age = cfg.state_max_age_seconds;
    if interval_seconds == 0 {
        info!("session/state sweeper disabled (session_sweep_interval_seconds=0)");
        return;
    }
    let sessions = Arc::clone(&sessions);
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_seconds));
        // Skip the immediate first tick — startup is busy enough.
        tick.tick().await;
        loop {
            tick.tick().await;
            match sessions.sweep_expired().await {
                Ok(n) if n > 0 => debug!(count = n, "swept expired sessions"),
                Ok(_) => {}
                Err(e) => warn!(error = %e, "session sweep failed"),
            }
            match sweep_oauth_state(&pool, state_max_age).await {
                Ok(n) if n > 0 => debug!(count = n, "swept stale oauth_state rows"),
                Ok(_) => {}
                Err(e) => warn!(error = %e, "oauth_state sweep failed"),
            }
        }
    });
}

async fn sweep_oauth_state(pool: &PgPool, max_age_seconds: u64) -> sqlx::Result<u64> {
    let res = sqlx::query(
        r#"
        DELETE FROM auth.oauth_state
              WHERE created_at < now() - ($1::text || ' seconds')::interval
        "#,
    )
    .bind(max_age_seconds.to_string())
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
