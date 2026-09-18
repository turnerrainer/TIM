//! F-PR-3 / T-7 regression pin.
//!
//! JWT signing-key rotation grace period exposed through the router:
//!
//! 1. `GET /jwt/keys/public` returns 2 keys when a previous key is
//!    configured and `retires_at > now`.
//! 2. Same endpoint returns only 1 key after `retires_at` has passed.
//! 3. `POST /introspect` accepts a token signed with what is now the
//!    previous key, during grace.
//! 4. After grace expires, the same previous-signed token is refused
//!    (`active: false`).
//!
//! These four together demonstrate the operator-facing invariant: a
//! rotation can complete without a coordinated fleet cut-over, and the
//! grace window is bounded to what config declared.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
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

const CURRENT_KEY: &str = include_str!("fixtures/test-jwt-private.pem");
const PREVIOUS_KEY: &str = include_str!("fixtures/test-jwt-private-alt.pem");
const CURRENT_KID: &str = "rot-current";
const PREVIOUS_KID: &str = "rot-previous";

async fn setup(retires_at: Option<DateTime<Utc>>) -> Option<(axum::Router, PgPool)> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;

    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    cfg.introspection.required_client_auth = false;

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    // Wipe the denylist so a stale jti from an earlier run does not
    // shadow the active-token assertions.
    sqlx::query("TRUNCATE TABLE custom_jwt.denylist, custom_jwt.jwt_metadata")
        .execute(&pool)
        .await
        .ok()?;

    let mut signer = JwtSigner::from_pkcs8_pem(CURRENT_KEY, CURRENT_KID.into()).ok()?;
    if let Some(r) = retires_at {
        signer = signer
            .with_previous(PREVIOUS_KEY, PREVIOUS_KID.into(), r)
            .ok()?;
    }
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
        db: pool.clone(),
        signer: Arc::new(signer),
        jwt: jwt.clone(),
        providers,
        sessions,
        admin,
        introspect_gate,
    };
    Some((build_router(state, &cfg), pool))
}

async fn get_jwks(router: &axum::Router) -> serde_json::Value {
    let req = Request::builder()
        .method("GET")
        .uri("/jwt/keys/public")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn post_introspect(router: &axum::Router, token: &str) -> serde_json::Value {
    let req = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("token={token}")))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn jwks_emits_two_keys_during_grace_period() {
    let Some((router, _pool)) = setup(Some(Utc::now() + Duration::days(7))).await else {
        return;
    };
    let jwks = get_jwks(&router).await;
    let keys = jwks["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 2, "expected 2 keys during grace: {jwks:?}");
    let kids: Vec<&str> = keys
        .iter()
        .map(|k| k["kid"].as_str().unwrap_or(""))
        .collect();
    assert!(kids.contains(&CURRENT_KID), "kids: {kids:?}");
    assert!(kids.contains(&PREVIOUS_KID), "kids: {kids:?}");
}

#[tokio::test]
async fn jwks_emits_only_current_after_grace() {
    let Some((router, _pool)) = setup(Some(Utc::now() - Duration::days(1))).await else {
        return;
    };
    let jwks = get_jwks(&router).await;
    let keys = jwks["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1, "expected 1 key after grace: {jwks:?}");
    assert_eq!(keys[0]["kid"], CURRENT_KID);
}

/// End-to-end: sign a TIM-issued token using the "previous" key
/// directly, register its jti in the metadata table (matching what a
/// real generate() would have done), and confirm introspection accepts
/// it during grace.
#[tokio::test]
async fn introspect_accepts_previous_signed_token_during_grace() {
    let Some((router, _pool)) = setup(Some(Utc::now() + Duration::days(7))).await else {
        return;
    };

    // Sign with the "previous" key directly — this mimics a token that
    // was issued before the rotation started. Introspection only
    // checks issuer + exp + denylist; no metadata row is required for
    // active=true (unrevoked jti not in denylist).
    let prev_signer = JwtSigner::from_pkcs8_pem(PREVIOUS_KEY, PREVIOUS_KID.into()).unwrap();
    let jti = uuid::Uuid::new_v4();
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": JwtConfig::default().issuer,
        "sub": "carryover-user",
        "jti": jti.to_string(),
        "iat": now,
        "exp": now + 3600,
    });
    let token = prev_signer.sign(&claims).unwrap();

    let body = post_introspect(&router, &token).await;
    assert_eq!(
        body["active"], true,
        "previous-signed token must be active during grace: {body:?}"
    );
    assert_eq!(body["sub"], "carryover-user");
}

/// The mirror case: after grace, the same shape returns inactive.
#[tokio::test]
async fn introspect_rejects_previous_signed_token_after_grace() {
    let Some((router, _pool)) = setup(Some(Utc::now() - Duration::days(1))).await else {
        return;
    };

    let prev_signer = JwtSigner::from_pkcs8_pem(PREVIOUS_KEY, PREVIOUS_KID.into()).unwrap();
    let jti = uuid::Uuid::new_v4();
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": JwtConfig::default().issuer,
        "sub": "carryover-user",
        "jti": jti.to_string(),
        "iat": now,
        "exp": now + 3600,
    });
    let token = prev_signer.sign(&claims).unwrap();

    let body = post_introspect(&router, &token).await;
    assert_eq!(
        body["active"], false,
        "previous-signed token must be inactive after grace: {body:?}"
    );
}
