//! Regression tests for AUDIT.md M2: `PostgresStore::get()` must not
//! run an ad-hoc DELETE on an expired session — that pattern racy'd
//! two concurrent gets and produced inconsistent 404/401 pairs. The
//! new implementation filters expired rows in the SELECT and leaves
//! reaping to `sweep_expired`.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool;
use tim::{
    config, db,
    oauth2::session::{PostgresStore, Session, SessionStore},
};

mod common;

async fn pool() -> Option<PgPool> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;
    let pool = db::connect(&db_url, &config::DatabaseConfig::default())
        .await
        .ok()?;
    db::run_migrations(&pool).await.ok()?;
    sqlx::query("TRUNCATE TABLE auth.session")
        .execute(&pool)
        .await
        .ok()?;
    Some(pool)
}

fn store(pool: PgPool) -> PostgresStore {
    // Same 32-byte hex key across tests; content doesn't matter because
    // we never introspect the plaintext.
    let key_hex = "77".repeat(32);
    let cipher =
        tim::oauth2::session::SessionCipher::from_hex_key(&key_hex).expect("cipher from hex key");
    PostgresStore::new(pool, Duration::from_secs(3600), cipher)
}

fn session(id: &str, ttl_seconds: i64) -> Session {
    let now = Utc::now();
    Session {
        id: id.into(),
        provider_id: "p".into(),
        user_id: "u".into(),
        created_at: now,
        last_activity: now,
        expires_at: now + chrono::Duration::seconds(ttl_seconds),
        profile: Default::default(),
    }
}

#[tokio::test]
async fn get_returns_none_for_expired_and_row_survives() {
    let Some(pool) = pool().await else {
        return;
    };
    let store = store(pool.clone());
    store.create(session("expired-1", -10)).await.unwrap();

    // GET must return None (session is past exp).
    let got = store.get("expired-1").await.unwrap();
    assert!(got.is_none());

    // Row must still exist — reaping is the sweeper's job now, not
    // get()'s. This is what closes the two-writer race.
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM auth.session WHERE id = $1")
        .bind("expired-1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "get() must not delete the row");

    // Sweeper reaps it.
    let swept = store.sweep_expired().await.unwrap();
    assert!(swept >= 1);
}

#[tokio::test]
async fn get_returns_session_when_not_expired() {
    let Some(pool) = pool().await else {
        return;
    };
    let store = store(pool);
    store.create(session("live-1", 60)).await.unwrap();
    assert!(store.get("live-1").await.unwrap().is_some());
}

#[tokio::test]
async fn concurrent_get_on_expired_produces_consistent_none() {
    let Some(pool) = pool().await else {
        return;
    };
    let store = Arc::new(store(pool));
    store.create(session("expired-2", -1)).await.unwrap();

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let s = store.clone();
        set.spawn(async move { s.get("expired-2").await.unwrap() });
    }
    while let Some(r) = set.join_next().await {
        assert!(r.unwrap().is_none(), "all concurrent gets must see None");
    }
}
