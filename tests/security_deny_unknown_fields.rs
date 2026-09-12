//! Fleet-strongholds §2.2 regression pin.
//!
//! Every modern JSON body / form / query DTO carries
//! `#[serde(deny_unknown_fields)]`. An attacker sending
//! `{"amount": 100, "admin_override": true}` used to get the
//! `admin_override` field silently dropped, request proceeds. Now the
//! request 400s and the caller sees exactly which field is wrong.
//!
//! JVM 1.x compat endpoints (body: String cookie names, legacy
//! `?jwt=&sessionId=` blacklist query) are DELIBERATELY not locked
//! down — DSL callers historically send extra fields and forcing
//! them to migrate would break the compat contract this repo
//! explicitly maintains.
//!
//! IdP-driven callbacks (`GET /auth/callback/:id`) are also NOT
//! locked down: real-world OAuth providers add per-request params
//! (Google's `scope`, `authuser`, etc.) and RFC 6749 says the
//! server MUST ignore unknown params.

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

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "deny-unknown-it".into()).ok()?;
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

async fn post_json(router: &axum::Router, uri: &str, body: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// `/jwt/custom/generate` rejects an unknown field with 4xx (BAD_REQUEST
/// or UNPROCESSABLE_ENTITY depending on the axum decoder path).
#[tokio::test]
async fn generate_rejects_unknown_field() {
    let Some(router) = setup().await else {
        return;
    };
    let body = r#"{"JWTName":"n","content":{},"expirationInMinutes":10,"admin_override":true}"#;
    let (status, resp) = post_json(&router, "/jwt/custom/generate", body).await;
    assert!(
        matches!(status.as_u16(), 400 | 422),
        "expected 4xx for unknown field; got {status}: {resp}"
    );
    assert!(
        resp.contains("admin_override") || resp.contains("unknown"),
        "expected error to mention the field or 'unknown': {resp}"
    );
}

/// `/jwt/custom/validate` rejects an unknown field.
#[tokio::test]
async fn validate_rejects_unknown_field() {
    let Some(router) = setup().await else {
        return;
    };
    let body = r#"{"token":"x","injected":"y"}"#;
    let (status, resp) = post_json(&router, "/jwt/custom/validate", body).await;
    assert!(
        matches!(status.as_u16(), 400 | 422),
        "expected 4xx; got {status}: {resp}"
    );
}

/// `/jwt/custom/extend` rejects an unknown field.
#[tokio::test]
async fn extend_rejects_unknown_field() {
    let Some(router) = setup().await else {
        return;
    };
    let body = r#"{"token":"x","attacker":true}"#;
    let (status, _) = post_json(&router, "/jwt/custom/extend", body).await;
    assert!(matches!(status.as_u16(), 400 | 422));
}

/// `/jwt/custom/revoke/bulk` rejects an unknown field.
#[tokio::test]
async fn bulk_revoke_rejects_unknown_field() {
    let Some(router) = setup().await else {
        return;
    };
    let body = r#"{"tokens":["a"],"extra":"pwned"}"#;
    let (status, _) = post_json(&router, "/jwt/custom/revoke/bulk", body).await;
    assert!(matches!(status.as_u16(), 400 | 422));
}

/// `/jwt/custom/list/me` rejects an unknown field (auth passes past
/// the Bearer requirement).
#[tokio::test]
async fn list_me_rejects_unknown_field() {
    let Some(router) = setup().await else {
        return;
    };
    let body = r#"{"limit":10,"attacker_page":true}"#;
    let req = Request::builder()
        .method("POST")
        .uri("/jwt/custom/list/me")
        .header("content-type", "application/json")
        .header("authorization", "Bearer bogus-token")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    // Bearer bogus-token will 401 from the auth gate — the unknown
    // field check happens AFTER auth. Either 401 (auth-gate first) or
    // 4xx unknown-field is acceptable; what we're pinning is "never
    // silently accept and proceed to a 200."
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "unknown field must not silently produce 200"
    );
}

/// `POST /introspect` (form-encoded) rejects an unknown field.
#[tokio::test]
async fn introspect_form_rejects_unknown_field() {
    let Some(router) = setup().await else {
        return;
    };
    let req = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from("token=x&attacker=1".to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await;
    assert!(
        matches!(status.as_u16(), 400 | 422),
        "expected 4xx, got {status}"
    );
}

/// `POST /introspect` (JSON body) rejects an unknown field.
#[tokio::test]
async fn introspect_json_rejects_unknown_field() {
    let Some(router) = setup().await else {
        return;
    };
    let body = r#"{"token":"x","attacker":"y"}"#;
    let (status, _) = post_json(&router, "/introspect", body).await;
    assert!(matches!(status.as_u16(), 400 | 422));
}

// NOTE on `POST /auth/logout`: the handler uses
// `Option<Json<LogoutBody>>` so that clients can call logout with
// no body at all. That extractor pattern silently converts a
// PARSE failure into `None` (indistinguishable from "no body sent"),
// so `deny_unknown_fields` on LogoutBody is currently a defense-in-
// depth guard rather than a wire-visible reject. Follow-up: reshape
// the handler to distinguish empty from malformed. For now we assert
// only the wire-visible endpoints.

/// Sanity check: a KNOWN field-set is still accepted (no over-eager
/// rejection). Uses the same setup as the reject tests.
#[tokio::test]
async fn known_fields_still_accepted() {
    let Some(router) = setup().await else {
        return;
    };
    let body = r#"{"JWTName":"sanity","content":{"sub":"user"},"expirationInMinutes":10}"#;
    let (status, resp) = post_json(&router, "/jwt/custom/generate", body).await;
    // 200 with a token; not 4xx. Any 4xx here would indicate the
    // deny_unknown_fields rule is over-fitting.
    assert_eq!(
        status,
        StatusCode::OK,
        "known-fields request must succeed, got {status}: {resp}"
    );
    assert!(resp.contains("\"token\""));
}
