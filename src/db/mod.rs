use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::DatabaseConfig;
use crate::error::{Result, TimError};

/// Build the pool with all tuning knobs (finding 24). Values with
/// `= 0` are treated as "unset" and left at sqlx defaults where
/// applicable.
pub async fn connect(url: &str, cfg: &DatabaseConfig) -> Result<PgPool> {
    let mut builder = PgPoolOptions::new()
        .min_connections(cfg.min_connections)
        .max_connections(cfg.max_connections);
    if cfg.acquire_timeout_seconds > 0 {
        builder = builder.acquire_timeout(Duration::from_secs(cfg.acquire_timeout_seconds));
    }
    if cfg.idle_timeout_seconds > 0 {
        builder = builder.idle_timeout(Duration::from_secs(cfg.idle_timeout_seconds));
    }
    if cfg.max_lifetime_seconds > 0 {
        builder = builder.max_lifetime(Duration::from_secs(cfg.max_lifetime_seconds));
    }
    // Test connections before handing them out — cheap in Postgres,
    // covers the "PgBouncer just recycled" case.
    builder = builder.test_before_acquire(true);
    let pool = builder.connect(url).await.map_err(TimError::Database)?;
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| TimError::Config(format!("migration failed: {e}")))?;
    Ok(())
}
