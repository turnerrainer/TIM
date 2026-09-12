//! Audit LOG-v1 FN-LOG-2 regression pin.
//!
//! Every completed HTTP request must emit at least one INFO line
//! carrying `http_request_completed` — the access-log invariant added
//! in `src/access_log.rs`. Fleet-strongholds §1.2: SOC2 CC7.2 /
//! ISO27001 A.12.4 access-logging.
//!
//! Also verifies the `trace_id` field is populated: either from a
//! valid W3C `traceparent` header or from a fresh generated id.

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
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "access-log-it".into()).ok()?;
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

async fn get(router: &axum::Router, path: &str, traceparent: Option<&str>) -> StatusCode {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(tp) = traceparent {
        b = b.header("traceparent", tp);
    }
    let req = b.body(axum::body::Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    // Drain the body so the response completes before we check logs.
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await;
    status
}

/// Send a batch of varied requests; assert the access-log middleware
/// emitted one `http_request_completed` line per completed request.
#[tokio::test]
async fn every_http_request_emits_one_access_log_line() {
    let buf = common::log_capture::install();
    let Some(router) = setup().await else {
        return;
    };

    let start = buf.len();
    for _ in 0..10 {
        let _ = get(&router, "/health", None).await;
    }
    // tokio yields to give the middleware time to log — the assertion
    // reads bytes from a Vec<u8> already flushed synchronously by the
    // formatter, so no sleep needed in practice.
    let delta = buf.slice_from(start);
    let text = String::from_utf8_lossy(&delta);
    let count = text.matches("http_request_completed").count();
    assert!(
        count >= 10,
        "expected ≥10 access log lines for 10 requests, got {}: {}",
        count,
        text
    );
}

/// A valid W3C traceparent must be preserved in the access log line
/// so Ruuter-emitted and TIM-emitted logs can be correlated.
#[tokio::test]
async fn traceparent_from_request_appears_in_access_log() {
    let buf = common::log_capture::install();
    let Some(router) = setup().await else {
        return;
    };

    let start = buf.len();
    // Any well-formed W3C traceparent: 00-<32 hex>-<16 hex>-<flags>.
    let trace = "aabbccddeeff00112233445566778899";
    let tp = format!("00-{trace}-1122334455667788-01");
    let status = get(&router, "/health", Some(&tp)).await;
    assert_eq!(status, StatusCode::OK);

    let delta = buf.slice_from(start);
    let text = String::from_utf8_lossy(&delta);
    assert!(
        text.contains("http_request_completed"),
        "no access log line in: {}",
        text
    );
    assert!(
        text.contains(trace),
        "trace_id `{}` not propagated to access log: {}",
        trace,
        text
    );
}

/// When no traceparent header is sent, the middleware must still
/// produce a fresh 32-char trace_id (fleet-strongholds §1.6).
#[tokio::test]
async fn access_log_populates_trace_id_when_header_absent() {
    let buf = common::log_capture::install();
    let Some(router) = setup().await else {
        return;
    };

    let start = buf.len();
    let status = get(&router, "/health", None).await;
    assert_eq!(status, StatusCode::OK);

    let delta = buf.slice_from(start);
    let text = String::from_utf8_lossy(&delta);
    let idx = text
        .find("trace_id=")
        .expect("trace_id field missing from access log");
    let after = &text[idx + "trace_id=".len()..];
    let end = after
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(after.len());
    let value = &after[..end];
    assert_eq!(
        value.len(),
        32,
        "trace_id `{value}` is not the fresh 32-char form (fleet §1.6)"
    );
}
