//! T-19 (h2ck.me v1 NEXT-TASKS) — comprehensive admin-surface audit.
//!
//! Enumerates every route in `src/router/mod.rs::build_router` and
//! pins that anything documented as `admin`/`bearer`/`session`/
//! `cookie` refuses an unauthenticated request. Anything documented
//! as public (`—`) is NOT tested here — those are exercised elsewhere.
//!
//! Rationale: h2ck.me PUBLIC-EXPOSURE-SUMMARY-v1 §AP-2 flagged that
//! we should confirm `TIM /introspect/types, /auth/providers — public
//! by-design` really is intended, and that no route is accidentally
//! public. This test locks the current gating shape in as a
//! regression pin, so any refactor of the extractor stack that
//! silently drops an `AdminAuth` / `SessionAuth` argument surfaces
//! at CI time rather than in production.
//!
//! What "unauth" means per route:
//! - **admin** — no `X-TIM-Admin-Token`, no `Authorization: Bearer <admin>` → 401
//! - **bearer** — no `Authorization: Bearer <jwt>` → 401
//! - **session** — no session transport (Bearer sess_, X-TIM-Session, ?session_id=) → 401
//! - **cookie** — no cookie → the compat handler returns 400 (JVM parity) or 401 depending on shape
//!
//! Body is omitted / minimal on POST routes; the gate must fire
//! before body parsing.

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
const ADMIN_ENV: &str = "TIM_ADMIN_TOKEN_AUDIT_IT";
const ADMIN_SECRET: &str = "test-admin-token-audit-32-b-abcdef";

async fn setup() -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;

    // Admin gate ENABLED — this is the production posture and the
    // only way the admin-401 assertions below are meaningful.
    std::env::set_var(ADMIN_ENV, ADMIN_SECRET);
    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = true;
    cfg.security.admin_token_env = ADMIN_ENV.into();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    // Introspection gate default is on (0.4.0-alpha FN1); we test
    // its 401 path separately (see tests/it_introspect_client_auth.rs
    // — this file only covers the admin/session/bearer/cookie axes).
    cfg.introspection.required_client_auth = false;

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "audit-it".into()).ok()?;
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

async fn status_of(router: &axum::Router, method: &str, uri: &str, body: &str) -> StatusCode {
    let mut b = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        b = b.header("content-type", "application/json");
    }
    let req = b.body(axum::body::Body::from(body.to_string())).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let s = resp.status();
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await;
    s
}

// ---------- admin-gated routes ----------

#[tokio::test]
async fn admin_routes_refuse_unauthenticated() {
    let Some(router) = setup().await else {
        return;
    };
    // (method, uri, minimal-body) — body content doesn't matter, the
    // AdminAuth extractor runs before Json<T>.
    let admin_routes: &[(&str, &str, &str)] = &[
        ("POST", "/jwt/custom/generate", "{}"),
        ("POST", "/jwt/custom/revoke", "{}"),
        ("POST", "/jwt/custom/revoke/bulk", "{}"),
        ("POST", "/jwt/custom/extend", "{}"),
        ("POST", "/jwt/custom-jwt-blacklist", ""),
        ("POST", "/jwt/custom-jwt-extend", ""),
        ("GET", "/jwt/extend-jwt-session", ""),
        ("POST", "/jwt/blacklist", ""),
    ];
    for (m, u, b) in admin_routes {
        let s = status_of(&router, m, u, b).await;
        assert_eq!(
            s,
            StatusCode::UNAUTHORIZED,
            "expected 401 on unauthenticated {m} {u}, got {s}"
        );
    }
}

// ---------- bearer-gated routes (TIM-issued JWT required) ----------

#[tokio::test]
async fn bearer_routes_refuse_missing_authorization() {
    let Some(router) = setup().await else {
        return;
    };
    // `POST /jwt/custom/list/me` requires `Authorization: Bearer
    // <TIM-issued JWT>` — no admin token, no session token.
    let s = status_of(&router, "POST", "/jwt/custom/list/me", "{}").await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "expected 401 on unauthenticated POST /jwt/custom/list/me, got {s}"
    );
}

// ---------- session-gated routes ----------

#[tokio::test]
async fn session_routes_refuse_missing_session_transport() {
    let Some(router) = setup().await else {
        return;
    };
    let session_routes: &[(&str, &str, &str)] = &[
        ("GET", "/auth/session/validate", ""),
        ("GET", "/auth/profile", ""),
        ("POST", "/auth/logout", ""),
    ];
    for (m, u, b) in session_routes {
        let s = status_of(&router, m, u, b).await;
        assert_eq!(
            s,
            StatusCode::UNAUTHORIZED,
            "expected 401 on session-less {m} {u}, got {s}"
        );
    }
}

// ---------- cookie-gated legacy compat routes ----------

/// `GET /jwt/userinfo` requires a cookie named `jwt.cookie_name`.
/// Missing cookie returns 400 (BadRequest) per the JVM shape.
#[tokio::test]
async fn compat_cookie_routes_refuse_missing_cookie() {
    let Some(router) = setup().await else {
        return;
    };
    let s = status_of(&router, "GET", "/jwt/userinfo", "").await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "expected 400 on cookie-less GET /jwt/userinfo, got {s}"
    );
}

// ---------- public routes should NOT 401 unauthenticated ----------

/// Negative-control: a small but explicit sample of the intended-
/// public set must NOT 401. Pins the "public by design" invariant.
///
/// If a future refactor accidentally gates one of these (e.g. adds
/// `_admin: AdminAuth` to `health()`), this test surfaces it. That is
/// the T-19 mirror invariant: neither too many nor too few gates.
#[tokio::test]
async fn documented_public_routes_do_not_401() {
    let Some(router) = setup().await else {
        return;
    };
    let public_routes: &[(&str, &str)] = &[
        ("GET", "/health"),
        ("GET", "/healthz"),
        ("GET", "/jwt/keys/public"),
        ("GET", "/jwt/verification-key"),
        ("GET", "/auth/providers"),
        ("GET", "/auth/health"),
    ];
    for (m, u) in public_routes {
        let s = status_of(&router, m, u, "").await;
        assert_ne!(
            s,
            StatusCode::UNAUTHORIZED,
            "public route {m} {u} unexpectedly returned 401"
        );
        assert_ne!(
            s,
            StatusCode::FORBIDDEN,
            "public route {m} {u} unexpectedly returned 403"
        );
    }
}
