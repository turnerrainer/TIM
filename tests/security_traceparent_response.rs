//! Fleet-strongholds §1.6 regression pin.
//!
//! Every HTTP response must carry a W3C `traceparent` header (compact
//! form: `x-trace-id`) so downstream services + tooling can correlate
//! request/response pairs without reading TIM's internal logs. When
//! the caller sent a valid `traceparent`, TIM's response echoes the
//! same trace-id back (with a fresh span-id — TIM is a new span in
//! the same trace). When absent, TIM generates a fresh trace-id.

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
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "traceparent-it".into()).ok()?;
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

async fn get_headers(
    router: &axum::Router,
    path: &str,
    traceparent: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap) {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(tp) = traceparent {
        b = b.header("traceparent", tp);
    }
    let req = b.body(axum::body::Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let _ = to_bytes(resp.into_body(), 1024 * 1024).await;
    (status, headers)
}

fn hex_str(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| b.is_ascii_hexdigit())
}

/// Every response carries a `traceparent` header. When no incoming
/// header is sent, TIM generates a fresh trace-id.
#[tokio::test]
async fn every_response_carries_traceparent_header() {
    let Some(router) = setup().await else {
        return;
    };
    let (status, headers) = get_headers(&router, "/health", None).await;
    assert_eq!(status, StatusCode::OK);
    let tp = headers
        .get("traceparent")
        .expect("traceparent missing on response")
        .to_str()
        .unwrap();
    let parts: Vec<&str> = tp.split('-').collect();
    assert_eq!(parts.len(), 4, "traceparent malformed: `{tp}`");
    assert_eq!(parts[0], "00", "version must be 00: `{tp}`");
    assert_eq!(parts[1].len(), 32, "trace-id must be 32 chars: `{tp}`");
    assert_eq!(parts[2].len(), 16, "span-id must be 16 chars: `{tp}`");
    assert_eq!(parts[3].len(), 2, "flags must be 2 chars: `{tp}`");
    assert!(hex_str(parts[1].as_bytes()));
    assert!(hex_str(parts[2].as_bytes()));
    assert!(hex_str(parts[3].as_bytes()));
    // Fresh generation defaults to sampled.
    assert_eq!(parts[3], "01");
}

/// `x-trace-id` echoes the same 32-char trace-id as the traceparent's
/// second segment.
#[tokio::test]
async fn every_response_carries_x_trace_id_header() {
    let Some(router) = setup().await else {
        return;
    };
    let (status, headers) = get_headers(&router, "/health", None).await;
    assert_eq!(status, StatusCode::OK);
    let tp = headers.get("traceparent").unwrap().to_str().unwrap();
    let x_trace = headers
        .get("x-trace-id")
        .expect("x-trace-id missing")
        .to_str()
        .unwrap();
    let expected_trace = tp.split('-').nth(1).unwrap();
    assert_eq!(x_trace, expected_trace);
}

/// Inheritance: an incoming valid traceparent's trace-id is echoed in
/// the response's traceparent (span-id must differ — TIM is a new
/// span, not the caller's span).
#[tokio::test]
async fn incoming_traceparent_trace_id_echoed_span_id_fresh() {
    let Some(router) = setup().await else {
        return;
    };
    let trace = "aabbccddeeff00112233445566778899";
    let span = "1122334455667788";
    let flags = "01";
    let incoming = format!("00-{trace}-{span}-{flags}");
    let (status, headers) = get_headers(&router, "/health", Some(&incoming)).await;
    assert_eq!(status, StatusCode::OK);
    let out = headers.get("traceparent").unwrap().to_str().unwrap();
    let parts: Vec<&str> = out.split('-').collect();
    assert_eq!(parts[1], trace, "trace-id must be inherited");
    assert_ne!(parts[2], span, "span-id must be fresh, not the caller's");
    // Sampling decision propagates.
    assert_eq!(parts[3], flags);
    // x-trace-id echoes the same trace_id.
    assert_eq!(headers.get("x-trace-id").unwrap().to_str().unwrap(), trace);
}

/// Unsampled decision (flags=00) from the caller must be preserved on
/// the response so downstream tooling honours the sampling budget.
#[tokio::test]
async fn unsampled_flag_from_caller_is_preserved() {
    let Some(router) = setup().await else {
        return;
    };
    let trace = "00112233445566778899aabbccddeeff";
    let incoming = format!("00-{trace}-1234567890abcdef-00");
    let (_, headers) = get_headers(&router, "/health", Some(&incoming)).await;
    let out = headers.get("traceparent").unwrap().to_str().unwrap();
    let flags = out.split('-').nth(3).unwrap();
    assert_eq!(flags, "00", "unsampled flag must propagate");
}

/// Malformed incoming traceparent → treated as absent, response
/// carries a fresh trace-id (not partial garbage).
#[tokio::test]
async fn malformed_incoming_traceparent_yields_fresh_trace_id() {
    let Some(router) = setup().await else {
        return;
    };
    // Too-short trace-id.
    let (_, headers) = get_headers(&router, "/health", Some("00-short-abcdef1234567890-01")).await;
    let out = headers.get("traceparent").unwrap().to_str().unwrap();
    let trace = out.split('-').nth(1).unwrap();
    assert_eq!(trace.len(), 32, "fresh trace-id when incoming malformed");
    assert_ne!(
        trace, "00000000000000000000000000000000",
        "invalid all-zero must not appear"
    );
}

/// Every 4xx / 5xx response ALSO carries the trace-id headers — the
/// worst time to lose observability is when errors happen.
#[tokio::test]
async fn error_responses_also_carry_trace_headers() {
    let Some(router) = setup().await else {
        return;
    };
    let (status, headers) = get_headers(&router, "/definitely-not-a-route", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        headers.get("traceparent").is_some(),
        "traceparent missing on 404"
    );
    assert!(
        headers.get("x-trace-id").is_some(),
        "x-trace-id missing on 404"
    );
}
