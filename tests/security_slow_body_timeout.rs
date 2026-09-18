//! T-15 probe: does TIM enforce `server.request_timeout_seconds`
//! on the body-read window, or does a slow trickle keep the request
//! alive indefinitely?
//!
//! Fleet-wide finding class: Ruuter et al have shown a shape where
//! the server accepts a request whose body dribbles in past the
//! documented per-request timeout, enabling a Slowloris-style
//! connection-exhaustion attack. h2ck.me marked this "not deeply
//! probed for TIM" (BREAK-TESTS-SUMMARY-v1 §Universal residuals #5).
//!
//! Probe shape: build a body stream that yields one byte, then sleeps
//! well beyond the configured `request_timeout_seconds`, then yields
//! the rest. TIM ships `tower_http::timeout::TimeoutLayer::new(
//! request_timeout)` wrapping the whole request future — this test
//! pins the invariant that the layer covers body-streaming too, not
//! just handler execution.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use futures_core::Stream;
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
/// Deliberately short so the probe finishes in a couple of seconds.
const TIMEOUT_SECONDS: u64 = 2;
/// Trickle delay — deliberately >> TIMEOUT_SECONDS so a functioning
/// timeout aborts long before this sleep completes.
const TRICKLE_DELAY: Duration = Duration::from_secs(8);

async fn setup() -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;

    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.server.request_timeout_seconds = TIMEOUT_SECONDS;
    cfg.oauth2.session_sweep_interval_seconds = 0;
    cfg.introspection.required_client_auth = false;

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "slow-it".into()).ok()?;
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(ProviderRegistry::from_config(&cfg.oauth2).await.ok()?);
    let sessions = Arc::new(MemoryStore::new(Duration::from_secs(60)));
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

/// Body stream that emits one byte immediately, then sleeps for
/// `TRICKLE_DELAY` before emitting the rest. Simulates a client that
/// opens the connection, sends headers + a token byte, then stalls.
///
/// Hand-rolled Stream impl to avoid pulling `futures-util` or
/// `tokio-stream` into dev-dependencies just for one probe.
struct SlowBody {
    step: u8,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Stream for SlowBody {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.step {
            0 => {
                self.step = 1;
                Poll::Ready(Some(Ok(Bytes::from_static(b"{"))))
            }
            1 => {
                if self.sleep.is_none() {
                    self.sleep = Some(Box::pin(tokio::time::sleep(TRICKLE_DELAY)));
                }
                match self.sleep.as_mut().unwrap().as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(()) => {
                        self.step = 2;
                        let tail = Bytes::from_static(
                            b"\"JWTName\":\"x\",\"content\":{},\"expirationInMinutes\":60}",
                        );
                        Poll::Ready(Some(Ok(tail)))
                    }
                }
            }
            _ => Poll::Ready(None),
        }
    }
}

fn slow_body() -> Body {
    Body::from_stream(SlowBody {
        step: 0,
        sleep: None,
    })
}

#[tokio::test]
async fn slow_body_aborts_within_request_timeout() {
    let Some(router) = setup().await else {
        return;
    };
    let req = Request::builder()
        .method("POST")
        .uri("/jwt/custom/generate")
        .header("content-type", "application/json")
        // No Content-Length header — body is streamed.
        .body(slow_body())
        .unwrap();

    let start = Instant::now();
    let resp = router.oneshot(req).await;
    let elapsed = start.elapsed();

    // Assert 1: elapsed must be within a small multiple of the
    // configured timeout. Give a generous margin (2x) so CI flake
    // doesn't false-positive; TRICKLE_DELAY is 8s, so anything under
    // ~5s proves the timeout fired.
    let bound = Duration::from_secs(TIMEOUT_SECONDS * 2 + 1);
    assert!(
        elapsed < bound,
        "request took {:?}; expected < {:?} (timeout = {}s, trickle = {:?})",
        elapsed,
        bound,
        TIMEOUT_SECONDS,
        TRICKLE_DELAY
    );

    // Assert 2: the response is either a proper 408/504 error OR the
    // service errors out with the timeout — either counts as "the
    // timeout fired." The exact StatusCode is a `tower_http` /
    // `axum` choice we don't want to pin too tightly; the elapsed
    // check above is the real invariant.
    match resp {
        Ok(r) => {
            let s = r.status();
            assert!(
                s == StatusCode::REQUEST_TIMEOUT
                    || s == StatusCode::GATEWAY_TIMEOUT
                    || s == StatusCode::SERVICE_UNAVAILABLE
                    || s.is_server_error(),
                "expected timeout-shaped status, got {s}"
            );
        }
        Err(_) => { /* connection-level abort also counts */ }
    }
}
