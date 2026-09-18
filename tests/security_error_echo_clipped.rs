//! BREAK-TESTS-OWASP-PROBES-v1 AP-6 regression pin.
//!
//! Every attacker-controlled fragment echoed back into an error
//! response must be clipped at 256 characters so a malformed request
//! cannot inflate the response body (log-flood, response-bomb, cache-
//! poisoning of downstream aggregators). Coverage:
//!
//! 1. `GET /auth/providers/<id>` — unknown provider id (Path).
//! 2. `GET /auth/login/<id>` — unknown provider id (Path).
//! 3. `GET /auth/callback/<id>?error=<x>&error_description=<y>` — the
//!    entire echo path for provider-side error redirects.
//! 4. `POST /introspect` with malformed JSON — parse-error echo.
//! 5. `POST /logout?jwt=<x>` — invalid UUID echo.

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
/// AP-6 cap. Must match `router::UNTRUSTED_ECHO_CAP` and the calls in
/// `oauth2/idtoken.rs`.
const CAP: usize = 256;

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
    // Not exercising the introspection auth axis in this suite.
    cfg.introspection.required_client_auth = false;

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "clip-it".into()).ok()?;
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

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post(router: &axum::Router, uri: &str, ct: &str, body: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", ct)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A 2KB attacker payload — well over the 256-char cap.
fn payload() -> String {
    "A".repeat(2048)
}

fn assert_no_full_payload(body: &str, payload: &str) {
    assert!(
        !body.contains(payload),
        "attacker payload of length {} echoed in full; body len {}",
        payload.len(),
        body.len()
    );
}

fn assert_clipped_ellipsis_present(body: &str) {
    // The clip helper appends `…` (U+2026) on truncation.
    assert!(
        body.contains('…'),
        "expected clipped ellipsis marker in body: {body}"
    );
}

#[tokio::test]
async fn provider_one_404_clips_id() {
    let Some(router) = setup().await else {
        return;
    };
    let p = payload();
    let (s, body) = get(&router, &format!("/auth/providers/{p}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_no_full_payload(&body, &p);
    assert_clipped_ellipsis_present(&body);
    // Sanity: the CAP prefix DID make it through.
    let leading: String = p.chars().take(CAP).collect();
    assert!(
        body.contains(&leading),
        "expected clipped leading {CAP} chars in body: {body}"
    );
}

#[tokio::test]
async fn login_404_clips_id() {
    let Some(router) = setup().await else {
        return;
    };
    let p = payload();
    let (s, body) = get(&router, &format!("/auth/login/{p}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_no_full_payload(&body, &p);
    assert_clipped_ellipsis_present(&body);
}

#[tokio::test]
async fn callback_error_query_clips_error_and_description() {
    let Some(router) = setup().await else {
        return;
    };
    let p_err = payload();
    let p_desc = "B".repeat(2048);
    let p_id = "C".repeat(2048);
    // urlencoded values — bytes are all safe ASCII so identity encode.
    let uri = format!("/auth/callback/{p_id}?error={p_err}&error_description={p_desc}");
    let (s, body) = get(&router, &uri).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_no_full_payload(&body, &p_err);
    assert_no_full_payload(&body, &p_desc);
    assert_no_full_payload(&body, &p_id);
    assert_clipped_ellipsis_present(&body);
    // Response body length is bounded by three clipped fields + JSON
    // scaffolding. Generous cap so we're pinning the invariant, not
    // an exact serializer output.
    assert!(
        body.len() < 4 * (CAP + 4) + 256,
        "response body length {} exceeds bound",
        body.len()
    );
}

#[tokio::test]
async fn introspect_json_parse_error_clips_detail() {
    let Some(router) = setup().await else {
        return;
    };
    // Build a JSON body that will fail parsing with a message that
    // (via serde_json's default error rendering) can include the
    // offending literal — clip that echo.
    let attacker_key = "K".repeat(2048);
    let body_in = format!(r#"{{"{attacker_key}":"x"}}"#);
    let (s, body) = post(&router, "/introspect", "application/json", &body_in).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_no_full_payload(&body, &attacker_key);
    // We do not assert on ellipsis here because serde_json's error
    // text may or may not include the offending key — the invariant
    // that matters is "no unbounded echo."
}

#[tokio::test]
async fn jwt_blacklist_bad_jwt_query_clips_echo() {
    let Some(router) = setup().await else {
        return;
    };
    let p = payload();
    // POST /jwt/blacklist?jwt=<attacker> — the compat blacklist route
    // (admin-only, but setup() disables admin auth). Bad UUID → 400
    // with attacker-supplied query echoed. Clip must apply.
    let (s, body) = post(
        &router,
        &format!("/jwt/blacklist?jwt={p}"),
        "application/x-www-form-urlencoded",
        "",
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_no_full_payload(&body, &p);
    assert_clipped_ellipsis_present(&body);
}
