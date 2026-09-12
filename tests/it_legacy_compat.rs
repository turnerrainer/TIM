//! Legacy Buerokratt-TIM endpoint compatibility.
//!
//! These endpoints preserve the shape the ~93 DSL files referencing
//! `check-user-authority.yml` and `logout.yml` expect.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{json, Value};
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
const ADMIN_ENV: &str = "TIM_ADMIN_TOKEN_COMPAT_IT";
const ADMIN_VAL: &str = "compat-admin-secret";

async fn setup() -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;
    let mut cfg = AppConfig::default();
    // Compat endpoints under test — enable the admin gate so we can
    // prove it's enforced on the blacklist endpoints (userinfo stays
    // public).
    cfg.security.require_admin_token = true;
    cfg.security.admin_token_env = ADMIN_ENV.into();
    std::env::set_var(ADMIN_ENV, ADMIN_VAL);
    cfg.oauth2.session_sweep_interval_seconds = 0;
    // 0.4.0-alpha (FN1): introspection default is now on; this test
    // does not exercise it — opt out explicitly.
    cfg.introspection.required_client_auth = false;

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    sqlx::query(
        "TRUNCATE TABLE custom_jwt.denylist, custom_jwt.jwt_metadata, \
         auth.oauth_state, auth.session",
    )
    .execute(&pool)
    .await
    .ok()?;

    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "compat-it".into()).ok()?;
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

async fn json_post_with_admin(
    router: &axum::Router,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("x-tim-admin-token", ADMIN_VAL)
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

async fn generate_token(router: &axum::Router, sub: &str) -> String {
    let body = json!({
        "JWTName": "compat",
        "content": {"sub": sub},
        "expirationInMinutes": 30,
    });
    let (s, v) = json_post_with_admin(router, "/jwt/custom/generate", body).await;
    assert_eq!(s, StatusCode::OK, "generate failed: {v:?}");
    v["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn userinfo_returns_claims_from_cookie() {
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "cookie-user").await;

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/userinfo")
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["userinfo"]["subject"], "cookie-user");
    assert_eq!(v["userinfo"]["issuer"], "TIM");
    // token_type claim (injected at generate) flows through.
    assert_eq!(v["userinfo"]["claims"]["token_type"], "custom_jwt");
}

#[tokio::test]
async fn userinfo_400s_when_cookie_missing() {
    let Some(router) = setup().await else {
        return;
    };
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/userinfo")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn userinfo_401s_when_token_revoked() {
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "revoked-user").await;
    let (_, _) = json_post_with_admin(
        &router,
        "/jwt/custom/revoke",
        json!({"token": token, "reason": "test"}),
    )
    .await;
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/userinfo")
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn userinfo_is_public_no_admin_token_needed() {
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "public-user").await;
    // NO x-tim-admin-token header.
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/userinfo")
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn custom_jwt_blacklist_by_cookie_name_body() {
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "blk-user").await;
    // Body is the cookie name; header carries the actual cookie.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-blacklist")
        .header("x-tim-admin-token", ADMIN_VAL)
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::from("jwt"))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["status"], "blacklisted");

    // Second call → 409 (idempotent).
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-blacklist")
        .header("x-tim-admin-token", ADMIN_VAL)
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::from("jwt"))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn custom_jwt_blacklist_requires_admin() {
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "admin-check").await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-blacklist")
        // deliberately no admin header
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::from("jwt"))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn blacklist_supports_all_three_modes() {
    let Some(router) = setup().await else {
        return;
    };
    // Mode 1: cookie
    let t1 = generate_token(&router, "mode-cookie").await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/blacklist")
        .header("x-tim-admin-token", ADMIN_VAL)
        .header("cookie", format!("jwt={t1}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Mode 2: ?jwt=<uuid> — extract jti from a valid token.
    let t2 = generate_token(&router, "mode-jti").await;
    let (_, validate) =
        json_post_with_admin(&router, "/jwt/custom/validate", json!({"token": t2})).await;
    let jti = validate["jwt_id"].as_str().unwrap().to_string();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/jwt/blacklist?jwt={jti}"))
        .header("x-tim-admin-token", ADMIN_VAL)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Second call → 409.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/jwt/blacklist?jwt={jti}"))
        .header("x-tim-admin-token", ADMIN_VAL)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Mode 3: ?sessionId=<id> — 404 when session doesn't exist (we
    // don't have OAuth2 session fixtures wired here; the 404 path
    // covers the branch).
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/blacklist?sessionId=nosuch")
        .header("x-tim-admin-token", ADMIN_VAL)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn blacklist_400s_when_no_mode_supplied() {
    let Some(router) = setup().await else {
        return;
    };
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/blacklist")
        .header("x-tim-admin-token", ADMIN_VAL)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn blacklist_by_jti_404s_when_unknown() {
    let Some(router) = setup().await else {
        return;
    };
    let bogus = uuid::Uuid::new_v4();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/jwt/blacklist?jwt={bogus}"))
        .header("x-tim-admin-token", ADMIN_VAL)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Additional legacy handlers added on the refacto-compliance branch —
// coverage-matrix rows E01, E05, E08, E10, E11.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verification_key_returns_pem_public_key() {
    // E01 — JVM 1.x GET /jwt/verification-key returned the JWT
    // signing public key as PEM. Legacy Java clients still parse
    // this shape.
    let Some(router) = setup().await else {
        return;
    };
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/verification-key")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).expect("utf-8 pem");
    // PKCS#1 shape — TIM emits "-----BEGIN RSA PUBLIC KEY-----".
    // Legacy Java also accepts SPKI "-----BEGIN PUBLIC KEY-----";
    // we only guarantee PKCS#1 today.
    assert!(
        body.starts_with("-----BEGIN RSA PUBLIC KEY-----"),
        "expected PKCS#1 PEM; got: {body}"
    );
    assert!(body.trim_end().ends_with("-----END RSA PUBLIC KEY-----"));
}

#[tokio::test]
async fn verification_key_is_public_no_admin_token_needed() {
    // Public key is public — must not require admin auth.
    let Some(router) = setup().await else {
        return;
    };
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/verification-key")
        // deliberately no header
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn custom_jwt_verify_by_cookie_name_body_ok_and_401() {
    // E08 — JVM 1.x POST /jwt/custom-jwt-verify with body = cookie
    // name. Reads that cookie from the request, verifies via the
    // same denylist-checked path as /jwt/custom/validate.
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "verify-user").await;

    // Happy path — cookie present, valid token → 200.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-verify")
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::from("jwt"))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["valid"], true);
    assert_eq!(v["active"], true);
    assert_eq!(v["subject"], "verify-user");

    // Cookie missing → 401 with `reason: "cookie_not_present"`.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-verify")
        .body(axum::body::Body::from("jwt"))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["reason"], "cookie_not_present");

    // Revoked token → 401.
    let _ = json_post_with_admin(&router, "/jwt/custom/revoke", json!({"token": token})).await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-verify")
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::from("jwt"))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn custom_jwt_userinfo_by_cookie_name_body_returns_claims() {
    // E11 — JVM 1.x POST /jwt/custom-jwt-userinfo. Body = cookie
    // name; server reads that cookie and returns the claims. Differs
    // from GET /jwt/userinfo (which reads the standard
    // `jwt.cookie_name`) in that the caller specifies which cookie
    // to consume.
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "userinfo-user").await;
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-userinfo")
        // Use a non-default cookie name to prove the body is what
        // drives the lookup (jwt.cookie_name default is "jwt").
        .header("cookie", format!("MY_APP_TOKEN={token}"))
        .body(axum::body::Body::from("MY_APP_TOKEN"))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["userinfo"]["subject"], "userinfo-user");
    assert_eq!(v["cookie_name"], "MY_APP_TOKEN");

    // Empty body → 400.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-userinfo")
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::from(""))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Named cookie not present → 400.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-userinfo")
        // no cookie header at all
        .body(axum::body::Body::from("SOME_COOKIE"))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn custom_jwt_extend_by_cookie_returns_new_set_cookie() {
    // E10 — JVM 1.x POST /jwt/custom-jwt-extend. Body = cookie name;
    // server reads that cookie, calls extend, returns the new token
    // via Set-Cookie under the same cookie name. Admin-gated per
    // audit gate.
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "extend-user").await;

    // Without admin token → 401.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-extend")
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::from("jwt"))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // With admin token + cookie → 200 + Set-Cookie for jwt.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/jwt/custom-jwt-extend")
        .header("x-tim-admin-token", ADMIN_VAL)
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::from("jwt"))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("Set-Cookie present")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        set_cookie.starts_with("jwt="),
        "Set-Cookie must use the same cookie name; got {set_cookie}"
    );
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Lax"));

    // Body: verify the new token is different from the old.
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    let new_token = v["token"].as_str().unwrap();
    assert_ne!(new_token, token, "extend must produce a fresh token");
    assert_eq!(v["status"], "extended");
}

#[tokio::test]
async fn extend_jwt_session_reads_default_cookie_and_returns_set_cookie() {
    // E05 — JVM 1.x GET /jwt/extend-jwt-session. Reads JWT from the
    // configured jwt.cookie_name cookie, extends, sets the refreshed
    // cookie. Admin-gated.
    let Some(router) = setup().await else {
        return;
    };
    let token = generate_token(&router, "session-extend-user").await;

    // Cookie present, admin token present → 200 + Set-Cookie.
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/extend-jwt-session")
        .header("x-tim-admin-token", ADMIN_VAL)
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .expect("Set-Cookie present")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        set_cookie.starts_with("jwt="),
        "expected 'jwt=...'; got {set_cookie}"
    );

    // No cookie → 400.
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/extend-jwt-session")
        .header("x-tim-admin-token", ADMIN_VAL)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // No admin token → 401.
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/jwt/extend-jwt-session")
        .header("cookie", format!("jwt={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
