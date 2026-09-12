//! Integration tests for OAuth2 endpoints that do not require an
//! upstream provider (health, providers list). Full callback tests
//! against a mock provider are backlog task (would need a fuller
//! OIDC mock than mockito's HTTP mock).

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::Value;
use tim::{
    config::{AppConfig, JwtConfig},
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::{session::MemoryStore, ProviderRegistry},
    router::{build_router, AppState},
    security::admin::AdminGate,
};
use tower::ServiceExt;

mod common;

const TEST_KEY: &str = include_str!("fixtures/test-jwt-private.pem");

async fn setup() -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;
    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    // 0.4.0-alpha (FN1): introspection default is now on; this test
    // does not exercise it — opt out explicitly.
    cfg.introspection.required_client_auth = false;
    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "oauth2-it".into()).ok()?;
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(ProviderRegistry::from_config(&cfg.oauth2).await.ok()?);
    let sessions = Arc::new(MemoryStore::new(std::time::Duration::from_secs(60)));
    let admin = AdminGate::from_config(&cfg.security).ok()?;
    let state = AppState {
        config: Arc::new(cfg.clone()),
        db: pool,
        signer: Arc::new(signer),
        jwt,
        providers,
        sessions,
        admin,
        introspect_gate: tim::security::IntrospectionGate::default(),
    };
    Some(build_router(state, &cfg))
}

async fn get(router: &axum::Router, path: &str) -> (StatusCode, Value) {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(path)
        .body(axum::body::Body::empty())
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
async fn providers_endpoint_returns_empty_when_no_providers_configured() {
    let Some(router) = setup().await else {
        return;
    };
    let (s, body) = get(&router, "/auth/providers").await;
    assert_eq!(s, StatusCode::OK);
    assert!(body["providers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn oauth2_health_returns_ok() {
    let Some(router) = setup().await else {
        return;
    };
    let (s, body) = get(&router, "/auth/health").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "oauth2");
    assert_eq!(body["available_providers"], 0);
}

#[tokio::test]
async fn unknown_provider_returns_404() {
    let Some(router) = setup().await else {
        return;
    };
    let (s, _) = get(&router, "/auth/providers/nope").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn login_unknown_provider_returns_404() {
    let Some(router) = setup().await else {
        return;
    };
    let (s, _) = get(&router, "/auth/login/nope").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn session_validate_missing_returns_404() {
    let Some(router) = setup().await else {
        return;
    };
    // Legacy ?session_id= transport still accepted (finding 27).
    let (s, _) = get(&router, "/auth/session/validate?session_id=nosuch").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn session_validate_without_id_is_unauthorized() {
    let Some(router) = setup().await else {
        return;
    };
    let (s, _) = get(&router, "/auth/session/validate").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
