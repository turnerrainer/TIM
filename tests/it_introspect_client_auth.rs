//! Regression tests for AUDIT.md H2: `POST /introspect` accepts
//! `introspection.required_client_auth = true` and, when set, rejects
//! every request that does not carry a valid Basic auth pair.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use tim::{
    config::{AppConfig, IntrospectionClient, JwtConfig},
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
const SECRET_ENV: &str = "TEST_INTROSPECT_IT_SECRET";
const SECRET_VAL: &str = "super-secret-value";
const CLIENT_ID: &str = "downstream-caller";

async fn setup(required: bool) -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;
    std::env::set_var(SECRET_ENV, SECRET_VAL);

    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    cfg.introspection.required_client_auth = required;
    cfg.introspection.clients = vec![IntrospectionClient {
        client_id: CLIENT_ID.into(),
        client_secret_env: SECRET_ENV.into(),
    }];

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "introspect-it".into()).ok()?;
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

fn basic(id: &str, secret: &str) -> String {
    format!("Basic {}", B64.encode(format!("{id}:{secret}").as_bytes()))
}

async fn post_introspect(
    router: &axum::Router,
    auth: Option<&str>,
    body: &str,
) -> (StatusCode, String) {
    let mut b = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let req = b.body(axum::body::Body::from(body.to_string())).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn required_auth_rejects_missing_authorization() {
    let Some(router) = setup(true).await else {
        return;
    };
    let (s, _b) = post_introspect(&router, None, "token=anything").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn required_auth_rejects_wrong_secret() {
    let Some(router) = setup(true).await else {
        return;
    };
    let (s, _b) = post_introspect(&router, Some(&basic(CLIENT_ID, "wrong")), "token=x").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn required_auth_rejects_unknown_client_id() {
    let Some(router) = setup(true).await else {
        return;
    };
    let (s, _b) = post_introspect(&router, Some(&basic("nobody", SECRET_VAL)), "token=x").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn required_auth_rejects_bearer_scheme() {
    let Some(router) = setup(true).await else {
        return;
    };
    let auth = format!("Bearer {SECRET_VAL}");
    let (s, _b) = post_introspect(&router, Some(&auth), "token=x").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn required_auth_accepts_valid_credentials() {
    let Some(router) = setup(true).await else {
        return;
    };
    // Valid Basic auth passes the gate; the token itself is bogus so
    // introspection returns 200 with {"active": false}. What we care
    // about here is 200 vs. 401 — the gate did its job.
    let (s, body) = post_introspect(
        &router,
        Some(&basic(CLIENT_ID, SECRET_VAL)),
        "token=notarealtoken",
    )
    .await;
    assert_eq!(s, StatusCode::OK, "body: {body}");
    assert!(body.contains("\"active\":false"), "body: {body}");
}

#[tokio::test]
async fn default_disabled_accepts_unauthenticated_request() {
    let Some(router) = setup(false).await else {
        return;
    };
    let (s, body) = post_introspect(&router, None, "token=notarealtoken").await;
    assert_eq!(s, StatusCode::OK, "body: {body}");
    assert!(body.contains("\"active\":false"));
}
