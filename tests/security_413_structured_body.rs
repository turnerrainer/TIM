//! Audit RUNTIME-v1 FN3 regression pin.
//!
//! `POST /jwt/custom/generate` with an oversize body must return a
//! structured JSON error body, not Axum's default bare-text
//! "Failed to buffer the request body: length limit exceeded".
//! Fleet-strongholds §2.3 / §6.1: every 4xx/5xx JSON-shaped.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use tim::{
    config::{AppConfig, JwtConfig},
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::{session::MemoryStore, ProviderRegistry},
    router::{build_router, AppState},
    security::{admin::AdminGate, introspect_auth::IntrospectionGate},
};
use tower::ServiceExt;

mod common;

const TEST_KEY: &str = include_str!("fixtures/test-jwt-private.pem");

async fn setup() -> Option<(axum::Router, usize)> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;

    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    // Small cap so the oversize body test is fast + memory-cheap.
    cfg.server.max_request_bytes = 4096;
    cfg.oauth2.session_sweep_interval_seconds = 0;

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "413-it".into()).ok()?;
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(ProviderRegistry::from_config(&cfg.oauth2).await.ok()?);
    let sessions = Arc::new(MemoryStore::new(std::time::Duration::from_secs(60)));
    let admin = AdminGate::from_config(&cfg.security).ok()?;
    let introspect_gate = IntrospectionGate::from_config(&cfg.introspection).ok()?;
    let max = cfg.server.max_request_bytes;
    let state = AppState {
        config: Arc::new(cfg.clone()),
        db: pool,
        signer: Arc::new(signer),
        jwt,
        providers,
        sessions,
        admin,
        introspect_gate,
    };
    Some((build_router(state, &cfg), max))
}

async fn post_oversize(router: &axum::Router, path: &str, size: usize) -> (StatusCode, String) {
    let big = vec![b'A'; size];
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("content-length", size.to_string())
        .body(axum::body::Body::from(big))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Preflight branch: an oversize `Content-Length` header is rejected
/// before the body is read. Assert 413 with structured JSON.
#[tokio::test]
async fn oversize_content_length_returns_json_413() {
    let Some((router, max)) = setup().await else {
        return;
    };
    // 2x the cap — well above the limit.
    let (status, body) = post_oversize(&router, "/jwt/custom/generate", max * 2).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "expected 413, got {}: {}",
        status,
        body
    );
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("body not JSON ({e}): {body}"));
    assert_eq!(v["error"], "payload_too_large", "body: {body}");
    assert_eq!(v["max"], max as u64, "body: {body}");
}

/// Streaming branch: request declares no content-length but streams
/// bytes past the cap. Send at cap+1 without a content-length header;
/// the DefaultBodyLimit layer's rejection is intercepted and mapped.
#[tokio::test]
async fn streamed_oversize_body_returns_json_413() {
    let Some((router, max)) = setup().await else {
        return;
    };
    let big = vec![b'A'; max + 1024];
    let req = Request::builder()
        .method("POST")
        .uri("/jwt/custom/generate")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(big))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "expected 413, got {}: {}",
        status,
        body
    );
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("body not JSON ({e}): {body}"));
    assert_eq!(v["error"], "payload_too_large", "body: {body}");
}

/// Response Content-Type on 413 must be application/json for
/// downstream JSON-parsing clients (Ruuter, JVM legacy callers).
#[tokio::test]
async fn oversize_413_response_has_json_content_type() {
    let Some((router, max)) = setup().await else {
        return;
    };
    let big = vec![b'A'; max * 2];
    let req = Request::builder()
        .method("POST")
        .uri("/jwt/custom/generate")
        .header("content-type", "application/json")
        .header("content-length", (max * 2).to_string())
        .body(axum::body::Body::from(big))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/json"),
        "expected application/json content-type, got: {}",
        ct
    );
}
