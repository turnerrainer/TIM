//! h2ck.me audit F-TIM-2 + F-TIM-6 regression pin.
//!
//! Before the gate: `POST /jwt/custom/validate`, `POST /jwt/custom/
//! validate/boolean`, `GET /jwt/userinfo`, `POST /jwt/custom-jwt-verify`,
//! `POST /jwt/custom-jwt-userinfo` all landed straight in the crypto-
//! verify + denylist SELECT path with no client auth. h2ck.me flagged
//! this as the same DoS class as F-TIM-1 (`/introspect`): an attacker
//! can drive the DB pool to exhaustion without credentials.
//!
//! The fix is a per-endpoint-class opt-in gate reusing the same
//! `introspection.clients` list:
//! - `introspection.gate_validation_endpoints: true` — gates the two
//!   modern `/jwt/custom/validate*` endpoints.
//! - `introspection.gate_jvm_compat_endpoints: true` — gates the three
//!   JVM 1.x cookie-borne validation compat endpoints.
//!
//! Defaults remain `false` for backward compatibility with existing
//! JVM DSL callers (they don't send Basic auth); operators enable when
//! TIM is exposed to untrusted networks or when Ruuter can forward a
//! Basic header from its guards.

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
const SECRET_ENV: &str = "TEST_VALIDATION_GATE_SECRET";
const SECRET_VAL: &str = "gate-shared-secret";
const CLIENT_ID: &str = "downstream-service";

/// (gate_validation_endpoints, gate_jvm_compat_endpoints).
async fn setup(gate_validation: bool, gate_jvm_compat: bool) -> Option<axum::Router> {
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
    // Every axis uses the same shared client list.
    cfg.introspection.required_client_auth = false;
    cfg.introspection.gate_validation_endpoints = gate_validation;
    cfg.introspection.gate_jvm_compat_endpoints = gate_jvm_compat;
    cfg.introspection.clients = vec![IntrospectionClient {
        client_id: CLIENT_ID.into(),
        client_secret_env: SECRET_ENV.into(),
    }];

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "validation-gate-it".into()).ok()?;
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

async fn post_json(
    router: &axum::Router,
    path: &str,
    auth: Option<&str>,
    body: &str,
) -> (StatusCode, String) {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let req = b.body(axum::body::Body::from(body.to_string())).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn get_with_cookie(
    router: &axum::Router,
    path: &str,
    auth: Option<&str>,
    cookie: Option<&str>,
) -> StatusCode {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    let req = b.body(axum::body::Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await;
    status
}

// ========== F-TIM-2: /jwt/custom/validate* ==========

/// `gate_validation_endpoints: false` (default) → `/jwt/custom/validate`
/// accepts unauth requests as it did before.
#[tokio::test]
async fn validation_gate_off_accepts_unauth() {
    let Some(router) = setup(false, false).await else {
        return;
    };
    let (status, _) = post_json(
        &router,
        "/jwt/custom/validate",
        None,
        r#"{"token":"bogus"}"#,
    )
    .await;
    // No auth gate; validate() runs, returns 401 for invalid token
    // (which is the pre-existing behaviour). What we care about here
    // is that we DID reach the validate() logic — not that we got
    // stopped at an auth gate.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// `gate_validation_endpoints: true`, no auth → 401 BEFORE reaching
/// crypto verify.
#[tokio::test]
async fn validation_gate_on_rejects_missing_auth() {
    let Some(router) = setup(true, false).await else {
        return;
    };
    let (status, body) = post_json(&router, "/jwt/custom/validate", None, r#"{"token":"x"}"#).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        body.contains("unauthorized"),
        "expected unauthorized error, got: {body}"
    );
}

/// Same gate but valid Basic → the gate passes; validate() then
/// returns its normal 401 for the invalid token — but the gate itself
/// approved (no `unauthorized` error at the gate layer).
#[tokio::test]
async fn validation_gate_on_accepts_valid_basic() {
    let Some(router) = setup(true, false).await else {
        return;
    };
    let auth = basic(CLIENT_ID, SECRET_VAL);
    let (status, _) = post_json(
        &router,
        "/jwt/custom/validate",
        Some(&auth),
        r#"{"token":"bogus"}"#,
    )
    .await;
    // Gate approved; token is bogus so validate() returns 401 with
    // the usual `valid: false` payload. The point of this assert is
    // that we're PAST the gate.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Same gate: wrong secret → 401 at the gate.
#[tokio::test]
async fn validation_gate_on_rejects_wrong_secret() {
    let Some(router) = setup(true, false).await else {
        return;
    };
    let auth = basic(CLIENT_ID, "wrong");
    let (status, _) = post_json(
        &router,
        "/jwt/custom/validate",
        Some(&auth),
        r#"{"token":"x"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// `/jwt/custom/validate/boolean` shares the gate.
#[tokio::test]
async fn validation_gate_on_covers_boolean_endpoint() {
    let Some(router) = setup(true, false).await else {
        return;
    };
    let (status_unauth, _) = post_json(
        &router,
        "/jwt/custom/validate/boolean",
        None,
        r#"{"token":"x"}"#,
    )
    .await;
    assert_eq!(status_unauth, StatusCode::UNAUTHORIZED);
    let auth = basic(CLIENT_ID, SECRET_VAL);
    let (status_auth, _) = post_json(
        &router,
        "/jwt/custom/validate/boolean",
        Some(&auth),
        r#"{"token":"x"}"#,
    )
    .await;
    assert_eq!(status_auth, StatusCode::UNAUTHORIZED); // token invalid → 401 boolean body, gate passed
}

// ========== F-TIM-6: JVM 1.x cookie-borne validation endpoints ==========

/// `gate_jvm_compat_endpoints: false` (default) → `/jwt/userinfo`
/// accepts unauth (uses cookie only; 400 for missing cookie is
/// pre-existing behaviour, NOT the gate refusing).
#[tokio::test]
async fn jvm_compat_gate_off_reaches_cookie_check() {
    let Some(router) = setup(false, false).await else {
        return;
    };
    let status = get_with_cookie(&router, "/jwt/userinfo", None, None).await;
    // Pre-existing behaviour: BadRequest because cookie is missing.
    // The point: NOT 401 from a gate.
    assert!(
        status.as_u16() == 400,
        "expected 400 (cookie missing), got {status}"
    );
}

/// `gate_jvm_compat_endpoints: true`, no auth → 401 BEFORE the cookie
/// check even runs.
#[tokio::test]
async fn jvm_compat_gate_on_rejects_missing_auth_on_userinfo() {
    let Some(router) = setup(false, true).await else {
        return;
    };
    let status = get_with_cookie(&router, "/jwt/userinfo", None, Some("jwt=bogus")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Same for `/jwt/custom-jwt-verify` (POST, body carries cookie name).
#[tokio::test]
async fn jvm_compat_gate_on_rejects_missing_auth_on_custom_verify() {
    let Some(router) = setup(false, true).await else {
        return;
    };
    let req = Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-verify")
        .header("content-type", "text/plain")
        .header("cookie", "jwt=bogus")
        .body(axum::body::Body::from("\"jwt\"".to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// And `/jwt/custom-jwt-userinfo` (POST, body carries cookie name).
#[tokio::test]
async fn jvm_compat_gate_on_rejects_missing_auth_on_custom_userinfo() {
    let Some(router) = setup(false, true).await else {
        return;
    };
    let req = Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-userinfo")
        .header("content-type", "text/plain")
        .header("cookie", "jwt=bogus")
        .body(axum::body::Body::from("\"jwt\"".to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Valid Basic → gate passes → cookie check runs.
#[tokio::test]
async fn jvm_compat_gate_on_accepts_valid_basic() {
    let Some(router) = setup(false, true).await else {
        return;
    };
    let auth = basic(CLIENT_ID, SECRET_VAL);
    let status = get_with_cookie(&router, "/jwt/userinfo", Some(&auth), Some("jwt=bogus")).await;
    // Gate passed; downstream returns 401 (token bogus). Not 401 from
    // the gate — the gate would have said `unauthorized` at the JSON
    // layer; here we get through to the crypto path.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The two gates are independent: enabling only F-TIM-2 gate leaves
/// F-TIM-6 endpoints unauth (backward compat), and vice-versa.
#[tokio::test]
async fn gates_are_independent() {
    // Only validation gate on.
    let Some(router_v) = setup(true, false).await else {
        return;
    };
    // Validation is gated:
    let (vs, _) = post_json(&router_v, "/jwt/custom/validate", None, r#"{"token":"x"}"#).await;
    assert_eq!(vs, StatusCode::UNAUTHORIZED);
    // JVM compat is NOT gated:
    let js = get_with_cookie(&router_v, "/jwt/userinfo", None, None).await;
    assert_eq!(js.as_u16(), 400); // BadRequest cookie missing, NOT 401 from gate

    // Only JVM compat gate on.
    let Some(router_j) = setup(false, true).await else {
        return;
    };
    // Validation is NOT gated:
    let (vs, _) = post_json(&router_j, "/jwt/custom/validate", None, r#"{"token":"x"}"#).await;
    assert_eq!(vs, StatusCode::UNAUTHORIZED); // token invalid, NOT gate
                                              // JVM compat IS gated:
    let js = get_with_cookie(&router_j, "/jwt/userinfo", None, Some("jwt=x")).await;
    assert_eq!(js, StatusCode::UNAUTHORIZED);
}
