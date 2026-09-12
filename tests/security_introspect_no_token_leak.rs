//! Audit LOG-v1 FN-LOG-3 regression pin (POSITIVE — pin the fleet
//! reference).
//!
//! `POST /introspect` must never echo the token content in logs,
//! at any severity level, on any error path. The h2ck.me break-tests
//! confirmed TIM's current behaviour is compliant; this test pins
//! the invariant so a future refactor of the debug log line in
//! `src/introspect/mod.rs` cannot silently regress into
//! `tracing::debug!(token = %req.token, "...")`.

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
const CANARY: &str = "CANARY-TOKEN-32B-abcdef0123456789abcdef";

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
    // 0.4.0-alpha (FN1): default requires introspection client auth.
    // This test exercises the token-content-in-log invariant, not the
    // auth axis — opt out so the handler proceeds past the gate.
    cfg.introspection.required_client_auth = false;

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "no-leak-it".into()).ok()?;
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(ProviderRegistry::from_config(&cfg.oauth2).await.ok()?);
    let sessions = Arc::new(MemoryStore::new(std::time::Duration::from_secs(60)));
    let admin = AdminGate::from_config(&cfg.security).ok()?;
    let introspect_gate = IntrospectionGate::from_config(&cfg.introspection).ok()?;
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
    Some(build_router(state, &cfg))
}

async fn post_introspect_form(router: &axum::Router, body: &str) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await;
    status
}

/// Send the canary as an opaque token via the standard form-encoded
/// path. The token is not a valid JWT, so the introspector falls into
/// the `token decode failed` debug log line. That line must not
/// contain the canary. The response body is `{"active": false}` (the
/// normal RFC 7662 uniform response) — we only assert on the log
/// stream.
#[tokio::test]
async fn form_encoded_invalid_token_does_not_leak_content() {
    let buf = common::log_capture::install();
    let Some(router) = setup().await else {
        return;
    };
    let start = buf.len();
    let body = format!("token={CANARY}");
    let status = post_introspect_form(&router, &body).await;
    assert_eq!(status, StatusCode::OK);

    let delta = buf.slice_from(start);
    let text = String::from_utf8_lossy(&delta);
    assert!(
        !text.contains(CANARY),
        "canary `{}` leaked into log: {}",
        CANARY,
        text
    );
}

/// Same test path but with token_type_hint set — exercises the
/// alternate branch in the form parser.
#[tokio::test]
async fn form_encoded_with_type_hint_does_not_leak_content() {
    let buf = common::log_capture::install();
    let Some(router) = setup().await else {
        return;
    };
    let start = buf.len();
    let body = format!("token={CANARY}&token_type_hint=access_token");
    let status = post_introspect_form(&router, &body).await;
    assert_eq!(status, StatusCode::OK);

    let delta = buf.slice_from(start);
    let text = String::from_utf8_lossy(&delta);
    assert!(
        !text.contains(CANARY),
        "canary `{}` leaked into log: {}",
        CANARY,
        text
    );
}

/// JSON-body branch: `application/json` `{ "token": "<canary>" }`
/// exercises `serde_json::from_slice::<IntrospectRequest>` — the
/// content-type discriminator in `router::introspect_dispatch`.
#[tokio::test]
async fn json_body_invalid_token_does_not_leak_content() {
    let buf = common::log_capture::install();
    let Some(router) = setup().await else {
        return;
    };
    let start = buf.len();
    let body = format!(r#"{{"token":"{CANARY}"}}"#);
    let req = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await;

    let delta = buf.slice_from(start);
    let text = String::from_utf8_lossy(&delta);
    assert!(
        !text.contains(CANARY),
        "canary `{}` leaked into log: {}",
        CANARY,
        text
    );
}
