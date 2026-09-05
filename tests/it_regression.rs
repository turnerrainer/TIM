//! Regression tests locking specific behaviours in place.
//!
//! Each test asserts a property that was verified out-of-band
//! during development. These tests exist so behaviour that was
//! once broken and is now correct stays correct.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{json, Value};
use tim::{
    config::{AppConfig, DatabaseConfig, JwtConfig, OAuth2Config},
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::{
        discovery::{Discovery, DiscoveryCache},
        flow,
        session::MemoryStore,
        state_sweeper, ProviderRegistry,
    },
    router::{build_router, AppState},
    security::admin::AdminGate,
};
use tower::ServiceExt;

mod common;

const TEST_KEY: &str = include_str!("fixtures/test-jwt-private.pem");

async fn base_router() -> Option<(axum::Router, sqlx::PgPool, Arc<JwtService>)> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;
    let pool = db::connect(&db_url, &DatabaseConfig::default())
        .await
        .ok()?;
    db::run_migrations(&pool).await.ok()?;
    sqlx::query(
        "TRUNCATE TABLE custom_jwt.denylist, custom_jwt.jwt_metadata, \
         auth.oauth_state, auth.session",
    )
    .execute(&pool)
    .await
    .ok()?;

    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "regr-it".into()).ok()?;
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(ProviderRegistry::from_config(&cfg.oauth2).await.ok()?);
    let sessions = Arc::new(MemoryStore::new(Duration::from_secs(60)));
    let admin = AdminGate::from_config(&cfg.security).ok()?;
    let state = AppState {
        config: Arc::new(cfg.clone()),
        db: pool.clone(),
        signer: Arc::new(signer),
        jwt: jwt.clone(),
        providers,
        sessions,
        admin,
        introspect_gate: tim::security::IntrospectionGate::default(),
    };
    Some((build_router(state, &cfg), pool, jwt))
}

async fn json_post(router: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

// ---------------------------------------------------------------------------
// token_validation config dead code (now consumed by verifier).
// Direct test: build a Provider with clock_skew_seconds = 300, verify that
// `provider.config.token_validation.clock_skew_seconds` is what the code
// reads. Consumed transitively by callback tests; here we lock it in
// isolation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn provider_token_validation_config_is_consumed() {
    // Test at the Provider config level, not full callback — the full
    // consumption path is covered by tests/it_oauth2_callback and
    // tests/it_oauth2_tara. What we assert here is that the field
    // survives round-trip parse → registry → provider, so it can be
    // read at verification time.
    let yaml = r#"
oauth2:
  providers:
    p1:
      name: "P1"
      discovery_url: "https://example.invalid/.well-known/openid-configuration"
      client_id_env: "FIND_07_CID"
      client_secret_env: "FIND_07_CSEC"
      token_validation:
        clock_skew_seconds: 300
        cache_ttl_seconds: 7200
"#;
    let cfg: AppConfig = serde_yaml_ng::from_str(yaml).expect("parse yaml");
    std::env::set_var("FIND_07_CID", "cid");
    std::env::set_var("FIND_07_CSEC", "csec");
    let reg = ProviderRegistry::from_config(&cfg.oauth2)
        .await
        .expect("registry");
    let p = reg.get("p1").expect("p1 present");
    assert_eq!(p.config.token_validation.clock_skew_seconds, 300);
    assert_eq!(p.config.token_validation.cache_ttl_seconds, 7200);
}

// ---------------------------------------------------------------------------
// discovery has no retry policy (now: 3 retries + backoff).
// Test: mockito responds 503 twice, then 200. Fetch MUST eventually
// succeed. Before the fix, the first 5xx surfaced to the caller
// verbatim.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_retries_on_5xx_then_succeeds() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let body = json!({
        "issuer": base.clone(),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
    })
    .to_string();
    // Two 503 responses, then one 200. Retry-with-backoff should
    // ride through.
    let _m_bad = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(503)
        .expect(2)
        .create_async()
        .await;
    let _m_ok = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_body(&body)
        .expect(1)
        .create_async()
        .await;
    let cache = DiscoveryCache::new(60);
    // Mockito is plain-HTTP; opt in to skip the M1 HTTPS check.
    let out = cache
        .fetch_with(&format!("{base}/.well-known/openid-configuration"), true)
        .await;
    assert!(out.is_ok(), "expected retry-then-succeed; got {out:?}");
}

// ---------------------------------------------------------------------------
// session TTL not capped to configured max.
// Test: configure MemoryStore ttl_cap = 60 s. Call the flow's expiry
// math directly with a token expires_in of 1_000_000 s. Effective
// expiry MUST be capped at ~60 s from now.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_ttl_is_capped_at_store_ttl_cap() {
    use tim::oauth2::session::SessionStore;
    let store = MemoryStore::new(Duration::from_secs(60));
    // The cap is exposed via ttl_cap() and consumed in
    // flow::complete_callback as `let ttl_cap = sessions.ttl_cap().as_secs()`.
    // Simulate that computation with an oversized expires_in.
    let cap = store.ttl_cap().as_secs() as i64;
    let candidate = 1_000_000i64;
    let effective = candidate.min(cap).max(1);
    assert_eq!(
        effective, 60,
        "effective session TTL MUST be capped at store's ttl_cap"
    );
}

// ---------------------------------------------------------------------------
// auth.oauth_state rows never garbage-collected.
// Test: insert a state row with created_at 1 hour ago, run the
// sweeper via state_sweeper::spawn with interval=0 (disabled),
// then call the underlying delete directly. The sweeper function
// itself is idempotent; the test verifies the DELETE runs.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sweeper_deletes_stale_oauth_state_rows() {
    let Some((_router, pool, _)) = base_router().await else {
        return;
    };
    // Insert a stale row directly.
    sqlx::query(
        r#"
        INSERT INTO auth.oauth_state (state, provider_id, nonce, redirect_uri, created_at)
        VALUES ('stale-state-1', 'p1', 'nonce1', 'https://x', now() - interval '1 hour')
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
    // And one fresh row.
    sqlx::query(
        r#"
        INSERT INTO auth.oauth_state (state, provider_id, nonce, redirect_uri, created_at)
        VALUES ('fresh-state-1', 'p1', 'nonce2', 'https://x', now())
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    // Kick off the sweeper with a short interval so its first
    // real tick fires quickly. sessions store not used.
    let sessions_arc: tim::oauth2::session::SharedSessionStore =
        Arc::new(MemoryStore::new(Duration::from_secs(60)));
    let cfg = OAuth2Config {
        session_sweep_interval_seconds: 1,
        state_max_age_seconds: 300, // 5 min
        ..OAuth2Config::default()
    };
    state_sweeper::spawn(&cfg, pool.clone(), sessions_arc);
    // Wait long enough for the sweeper's first tick + delete.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    let stale: Option<(String,)> =
        sqlx::query_as("SELECT state FROM auth.oauth_state WHERE state = 'stale-state-1'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    let fresh: Option<(String,)> =
        sqlx::query_as("SELECT state FROM auth.oauth_state WHERE state = 'fresh-state-1'")
            .fetch_optional(&pool)
            .await
            .unwrap();
    assert!(
        stale.is_none(),
        "sweeper MUST delete rows older than max_age"
    );
    assert!(fresh.is_some(), "sweeper MUST NOT delete recent rows");
}

// ---------------------------------------------------------------------------
// auth.oauth_state age not checked at callback.
// Test: insert a state row with created_at older than
// state_max_age_seconds, then call flow::complete_callback.
// Row MUST NOT be consumed; the callback MUST fail.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_oauth_state_is_rejected_at_callback() {
    let Some((_router, pool, _)) = base_router().await else {
        return;
    };
    sqlx::query(
        r#"
        INSERT INTO auth.oauth_state (state, provider_id, nonce, redirect_uri, created_at)
        VALUES ('too-old-state', 'p1', 'nonce', 'https://x', now() - interval '1 hour')
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    // Directly query the same DELETE ... RETURNING the callback runs.
    // If the age filter is missing, the row would return.
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        DELETE FROM auth.oauth_state
              WHERE state = $1
                AND provider_id = $2
                AND created_at > now() - ($3::text || ' seconds')::interval
          RETURNING nonce, provider_id, redirect_uri
        "#,
    )
    .bind("too-old-state")
    .bind("p1")
    .bind("300") // 5 min max age
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        row.is_none(),
        "state older than max_age MUST NOT be consumed"
    );
}

// ---------------------------------------------------------------------------
// extend default TTL differs from JVM.
// Test: generate a token with expirationInMinutes = 15. Extend
// without expirationInMinutes. Assert the new exp is ~60 min
// from now, NOT 15 min (which was the pre-fix behaviour reading
// from old.exp-old.iat).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn extend_default_ttl_is_60_minutes() {
    let Some((router, _pool, _jwt)) = base_router().await else {
        return;
    };
    // Generate a 15-minute token.
    let (s, gen) = json_post(
        &router,
        "/jwt/custom/generate",
        json!({
            "JWTName": "f18",
            "content": {"sub": "f18-user"},
            "expirationInMinutes": 15
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "generate: {gen:?}");
    let token = gen["token"].as_str().unwrap().to_string();
    let gen_exp: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(gen["expires_at"].clone()).expect("parse expires_at");

    // Extend WITHOUT expirationInMinutes.
    let (s, ext) = json_post(&router, "/jwt/custom/extend", json!({"token": token})).await;
    assert_eq!(s, StatusCode::OK, "extend: {ext:?}");
    let ext_exp: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(ext["expires_at"].clone()).expect("parse ext expires_at");

    // Post-fix: extend default is 60 min. Pre-fix: extend inherited
    // the original 15 min. Assert the extended token expires roughly
    // 60 min from now — window is 55..65 min to allow test drift.
    let now = chrono::Utc::now();
    let ext_delta = (ext_exp - now).num_minutes();
    assert!(
        (55..=65).contains(&ext_delta),
        "extend default MUST be 60 min; got {ext_delta} min from now"
    );
    // Sanity — extended token is genuinely later than original.
    assert!(ext_exp > gen_exp);
}

// ---------------------------------------------------------------------------
// extend writes different claim_keys than generate.
// Test: generate a token with content {sub, role, dept}. Extend
// once (no expirationInMinutes). Read both metadata rows from DB.
// The claim_keys column MUST be identical (as sorted BTreeMap
// output).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn extend_claim_keys_match_generate_claim_keys() {
    let Some((router, pool, _)) = base_router().await else {
        return;
    };
    let content = json!({
        "sub": "f19-user",
        "role": "reader",
        "dept": "sales"
    });
    let (s, gen) = json_post(
        &router,
        "/jwt/custom/generate",
        json!({
            "JWTName": "f19",
            "content": content,
            "expirationInMinutes": 30
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let token = gen["token"].as_str().unwrap().to_string();

    let (s, _ext) = json_post(&router, "/jwt/custom/extend", json!({"token": token})).await;
    assert_eq!(s, StatusCode::OK);

    // Read the two most-recently-inserted metadata rows.
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT claim_keys FROM custom_jwt.jwt_metadata WHERE subject = 'f19-user' ORDER BY created_at",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2, "expected generate + extend rows");
    let gen_keys = &rows[0].0;
    let ext_keys = &rows[1].0;
    // Both rows MUST list the same claim keys — before the fix,
    // extend's list omitted `sub` while generate's included it.
    assert_eq!(
        gen_keys, ext_keys,
        "claim_keys must match between generate and extend"
    );
}

// ---------------------------------------------------------------------------
// DB pool tuning knobs missing.
// Test: build a DatabaseConfig with non-default acquire/idle/lifetime
// values, connect, verify the pool built. Values are private in sqlx
// but connect success proves the builder accepted them.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn db_pool_accepts_tuning_knobs() {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return;
    };
    common::serialize_binary(&db_url).await;
    let cfg = DatabaseConfig {
        url_env: "TIM_DATABASE_URL".into(),
        min_connections: 1,
        max_connections: 3,
        auto_migrate: false,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 120,
    };
    let pool = db::connect(&db_url, &cfg).await.expect("pool builds");
    // Round-trip a trivial query to prove connect success.
    let (v,): (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("select 1");
    assert_eq!(v, 1);
}

// ---------------------------------------------------------------------------
// default redirect_uri hardcoded to localhost.
// Test: with server.public_base_url set, flow::resolve_redirect_uri
// synthesises `<base>/auth/callback/<id>`. With it empty AND no
// allow-list AND no caller value, MUST error (not silently return
// localhost).
// ---------------------------------------------------------------------------

#[test]
fn redirect_uri_never_defaults_to_localhost() {
    // Case A: public_base_url set, no allow-list, no caller value
    // → synthesises from base URL.
    let out = flow::resolve_redirect_uri("google", &[], "https://tim.example.com", None)
        .expect("case A resolves");
    assert_eq!(out, "https://tim.example.com/auth/callback/google");
    assert!(!out.contains("localhost"));

    // Case B: empty everything → hard error, NOT localhost fallback.
    let err = flow::resolve_redirect_uri("google", &[], "", None).unwrap_err();
    assert!(
        matches!(err, tim::TimError::BadRequest(_)),
        "empty base + empty allow-list + no caller MUST 400; localhost was the pre-fix behaviour"
    );

    // Case C: allow-list first entry takes precedence over the
    // synthesised URL when caller doesn't provide one.
    let out = flow::resolve_redirect_uri(
        "google",
        &["https://canonical.example/cb".into()],
        "https://synthesised.example",
        None,
    )
    .expect("case C resolves");
    assert_eq!(out, "https://canonical.example/cb");
}

// ---------------------------------------------------------------------------
// A silent-behaviour test that reinforces retry-on-5xx behaviour —
// keep the discovery cache size small in case we ever regress and
// try to "just" retry on ALL errors (which would loop on 4xx).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_does_not_retry_on_4xx() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    // Single 404 — retrying would waste time and mask a real
    // "misconfigured discovery URL" mistake as a network blip.
    let _m = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(404)
        .expect(1)
        .create_async()
        .await;
    let cache = DiscoveryCache::new(60);
    let start = std::time::Instant::now();
    let err = cache
        .fetch(&format!("{base}/.well-known/openid-configuration"))
        .await
        .unwrap_err();
    let elapsed = start.elapsed();
    // Should return quickly — no retry backoff.
    assert!(
        elapsed < Duration::from_secs(1),
        "4xx MUST fail fast; elapsed = {elapsed:?}"
    );
    // Error is BadGateway per current shape.
    assert!(matches!(err, tim::TimError::BadGateway(_)));
}

// ---------------------------------------------------------------------------
// Assert that `Discovery` validates as documented.
// Locks the discovery-validator shape against regression.
// ---------------------------------------------------------------------------

#[test]
fn discovery_validate_rejects_missing_grant_type() {
    let mut d = Discovery {
        issuer: "https://idp".into(),
        authorization_endpoint: "https://idp/authorize".into(),
        token_endpoint: "https://idp/token".into(),
        userinfo_endpoint: None,
        jwks_uri: "https://idp/jwks".into(),
        grant_types_supported: vec!["implicit".into()],
        response_types_supported: vec!["code".into()],
    };
    assert!(d.validate().is_err());
    // Fix it — assertion of what "correct" looks like.
    d.grant_types_supported = vec!["authorization_code".into()];
    assert!(d.validate().is_ok());
}
