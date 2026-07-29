//! End-to-end integration tests for the custom JWT lifecycle.
//!
//! Requires a real Postgres reachable at `TIM_DATABASE_URL`. In CI
//! this is a service container; locally run `docker compose up -d
//! postgres` first. Tests SKIP with a clear message if the env var
//! is missing so `cargo test` on a machine without Postgres does
//! not fail spuriously — see DEV-REQUIREMENTS §3 (no mocking DBs).

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{json, Value};
use tim_on_rust::{
    config::{AppConfig, JwtConfig},
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::{session::MemoryStore, ProviderRegistry},
    router::{build_router, AppState},
};
use tower::ServiceExt;

const TEST_KEY: &str = include_str!("fixtures/test-jwt-private.pem");

async fn setup() -> Option<(AppState, axum::Router)> {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("tim_on_rust=debug")),
        )
        .try_init();
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set (see DEV-REQUIREMENTS §3)");
        return None;
    };
    let cfg = AppConfig::default();
    let pool = db::connect(&db_url, &cfg.database).await.expect("connect");
    db::run_migrations(&pool).await.expect("migrate");

    // Tests share the schema; wipe rows for isolation. This is safe
    // because the CI database is a throwaway service container.
    sqlx::query("TRUNCATE TABLE custom_jwt.denylist, custom_jwt.jwt_metadata, auth.oauth_state")
        .execute(&pool)
        .await
        .expect("truncate");

    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "it-key".into()).expect("signer");
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(
        ProviderRegistry::from_config(&cfg.oauth2)
            .await
            .expect("registry"),
    );
    let sessions = Arc::new(MemoryStore::new(std::time::Duration::from_secs(60)));
    let state = AppState {
        config: Arc::new(cfg.clone()),
        db: pool,
        signer: Arc::new(signer),
        jwt,
        providers,
        sessions,
    };
    let router = build_router(state.clone(), &cfg);
    Some((state, router))
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
    let v: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, v)
}

#[tokio::test]
async fn generate_validate_revoke_extend_flow() {
    let Some((_state, router)) = setup().await else {
        return;
    };

    // 1. generate
    let (s, body) = json_post(
        &router,
        "/jwt/custom/generate",
        json!({"JWTName":"it","content":{"sub":"user-42","role":"admin"},"expirationInMinutes":10}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "generate failed: {body:?}");
    let token = body["token"].as_str().expect("token").to_string();
    assert!(!token.is_empty());
    assert_eq!(body["jwt_name"], "it");

    // 2. validate returns active
    let (s, body) = json_post(&router, "/jwt/custom/validate", json!({"token": token})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["valid"], true, "body={body}");
    assert_eq!(body["active"], true);
    assert_eq!(body["subject"], "user-42");
    assert_eq!(body["claims"]["role"], "admin");

    // 3. boolean variant returns "true"
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom/validate/boolean")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(json!({"token": token}).to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), "true");

    // 4. extend produces a new token, old one goes to denylist
    let (s, ext_body) = json_post(
        &router,
        "/jwt/custom/extend",
        json!({"token": token, "expirationInMinutes": 30}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "extend failed: {ext_body:?}");
    let new_token = ext_body["token"].as_str().expect("new token").to_string();
    assert_ne!(new_token, token);

    // Old token now revoked.
    let (_s, body) = json_post(&router, "/jwt/custom/validate", json!({"token": token})).await;
    assert_eq!(body["active"], false);
    assert_eq!(body["reason"], "revoked");

    // 5. revoke the new one
    let (s, body) = json_post(
        &router,
        "/jwt/custom/revoke",
        json!({"token": new_token, "reason": "it cleanup"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["status"], "revoked");

    // Idempotent
    let (_s, body) = json_post(&router, "/jwt/custom/revoke", json!({"token": new_token})).await;
    assert_eq!(body["status"], "already");
}

#[tokio::test]
async fn bulk_revoke_reports_counts() {
    let Some((_state, router)) = setup().await else {
        return;
    };
    let mut tokens = Vec::new();
    for i in 0..3 {
        let (_, body) = json_post(
            &router,
            "/jwt/custom/generate",
            json!({"JWTName":"bulk","content":{"sub":format!("bulk-{i}")},"expirationInMinutes":5}),
        )
        .await;
        tokens.push(body["token"].as_str().unwrap().to_string());
    }

    let (s, body) = json_post(
        &router,
        "/jwt/custom/revoke/bulk",
        json!({"tokens": tokens, "reason": "bulk it"}),
    )
    .await;
    assert!(s.is_success() || s == StatusCode::MULTI_STATUS);
    assert_eq!(body["newly_revoked"], 3);
    assert_eq!(body["already_revoked"], 0);
    assert_eq!(body["failed"], 0);
}

#[tokio::test]
async fn introspect_reports_active_then_revoked() {
    let Some((_state, router)) = setup().await else {
        return;
    };
    let (_, gen) = json_post(
        &router,
        "/jwt/custom/generate",
        json!({"JWTName":"int","content":{"sub":"introspect"},"expirationInMinutes":5}),
    )
    .await;
    let token = gen["token"].as_str().unwrap().to_string();

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("token={token}")))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["active"], true, "body={body}");
    assert_eq!(body["sub"], "introspect");
    assert_eq!(body["token_type"], "custom_jwt");

    // Revoke via /jwt/custom/revoke then re-introspect.
    let _ = json_post(&router, "/jwt/custom/revoke", json!({"token": token})).await;

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(json!({"token": token}).to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["active"], false);
}

#[tokio::test]
async fn list_me_requires_bearer_and_filters_by_subject() {
    let Some((_state, router)) = setup().await else {
        return;
    };
    // Generate a token for subject "list-me-user"
    let (_, gen) = json_post(
        &router,
        "/jwt/custom/generate",
        json!({"JWTName":"lm","content":{"sub":"list-me-user"},"expirationInMinutes":30}),
    )
    .await;
    let token = gen["token"].as_str().unwrap().to_string();

    // Also generate one for a different subject (should not appear).
    let _ = json_post(
        &router,
        "/jwt/custom/generate",
        json!({"JWTName":"lm2","content":{"sub":"other-user"},"expirationInMinutes":30}),
    )
    .await;

    // Missing Authorization → 401
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom/list/me")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // With bearer → 200 and only own tokens.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom/list/me")
        .header("authorization", format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let tokens = body["tokens"].as_array().unwrap();
    assert!(!tokens.is_empty());
    for t in tokens {
        assert_eq!(t["subject"], "list-me-user", "leaked another sub");
    }
}

#[tokio::test]
async fn health_and_jwks_do_not_require_db_state() {
    let Some((_state, router)) = setup().await else {
        return;
    };
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/keys/public")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let key = &body["keys"][0];
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["kid"], "it-key");
}

#[tokio::test]
async fn generate_rejects_zero_expiration() {
    let Some((_state, router)) = setup().await else {
        return;
    };
    let (s, _) = json_post(
        &router,
        "/jwt/custom/generate",
        json!({"JWTName":"bad","content":{},"expirationInMinutes":0}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn generate_rejects_oversize_payload() {
    let Some((_state, router)) = setup().await else {
        return;
    };
    let huge = "x".repeat(40_000); // > 32k default
    let (s, _) = json_post(
        &router,
        "/jwt/custom/generate",
        json!({"JWTName":"big","content":{"blob":huge},"expirationInMinutes":10}),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}
