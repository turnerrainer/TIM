//! Regression test for AUDIT.md H3: OAuth `state` consumption must be
//! race-safe. `DELETE ... RETURNING` in Postgres is atomic under the
//! default READ COMMITTED isolation — N concurrent callbacks with the
//! same `state` value must produce exactly one winner, N-1 misses.
//!
//! Also asserts the age guard: an aged-past-cap row cannot be consumed
//! even if the sweeper hasn't reaped it yet (closes the sweeper vs.
//! consumer race).

use sqlx::PgPool;
use tim::{config, db};

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
    sqlx::query("TRUNCATE TABLE auth.oauth_state")
        .execute(&pool)
        .await
        .ok()?;
    Some(pool)
}

async fn consume_state(pool: &PgPool, state: &str, max_age: u64) -> sqlx::Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        DELETE FROM auth.oauth_state
              WHERE state = $1
                AND provider_id = 'p'
                AND created_at > now() - make_interval(secs => $2::int)
          RETURNING nonce
        "#,
    )
    .bind(state)
    .bind(max_age as i32)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(n,)| n))
}

#[tokio::test]
async fn concurrent_state_consume_produces_exactly_one_winner() {
    let Some(pool) = pool().await else {
        return;
    };
    let state = "race-state-1";
    sqlx::query(
        "INSERT INTO auth.oauth_state (state, provider_id, nonce, redirect_uri) \
         VALUES ($1, 'p', 'n', 'u')",
    )
    .bind(state)
    .execute(&pool)
    .await
    .unwrap();

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let p = pool.clone();
        let s = state.to_string();
        set.spawn(async move { consume_state(&p, &s, 300).await.unwrap() });
    }
    let mut winners = 0;
    let mut misses = 0;
    while let Some(res) = set.join_next().await {
        match res.unwrap() {
            Some(_) => winners += 1,
            None => misses += 1,
        }
    }
    assert_eq!(winners, 1, "exactly one caller must win the DELETE");
    assert_eq!(misses, 31);
}

#[tokio::test]
async fn expired_row_cannot_be_consumed_even_before_sweeper_runs() {
    let Some(pool) = pool().await else {
        return;
    };
    let state = "aged-state-1";
    sqlx::query(
        "INSERT INTO auth.oauth_state (state, provider_id, nonce, redirect_uri, created_at) \
         VALUES ($1, 'p', 'n', 'u', now() - interval '10 minutes')",
    )
    .bind(state)
    .execute(&pool)
    .await
    .unwrap();

    // 300 s cap; row is 10 minutes old.
    let got = consume_state(&pool, state, 300).await.unwrap();
    assert!(got.is_none(), "aged row must not be consumable");

    // Row is still present (the sweeper would remove it separately).
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM auth.oauth_state WHERE state = $1")
        .bind(state)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "aged row is not touched by the consumer");
}

#[tokio::test]
async fn unknown_state_returns_none() {
    let Some(pool) = pool().await else {
        return;
    };
    let got = consume_state(&pool, "no-such-state", 300).await.unwrap();
    assert!(got.is_none());
}
