//! OTLP trace export: request (SERVER) spans, outbound OIDC (CLIENT) spans,
//! data exclusion and exporter configuration.
//!
//! Before this change TIM had no span export: `OTEL_EXPORTER_OTLP_*` was
//! ignored and the response `traceparent` named a random span id that no
//! exported span carried. These tests drive the router with an in-memory
//! exporter behind the same `observability::layer` the binary installs.
//!
//! With export OFF nothing changes; that path stays covered by
//! `security_traceparent_response.rs` and `security_log_access_present.rs`.
//!
//! Every test in this binary flips the process-global "export active" flag
//! on, so no test here may assert export-off behaviour. Router tests need
//! `TIM_DATABASE_URL` (skipped otherwise, like the other `it_*` binaries).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use futures_core::future::BoxFuture;
use opentelemetry::trace::{SpanId, SpanKind, Status};
use opentelemetry_sdk::export::trace::{ExportResult, SpanData, SpanExporter};
use opentelemetry_sdk::trace::TracerProvider;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use tim::{
    config::{AppConfig, JwtConfig, ProviderConfig, TokenValidationConfig},
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::{session::MemoryStore, ProviderRegistry},
    observability,
    router::{build_router, AppState},
    security::admin::AdminGate,
};
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

mod common;

const TEST_KEY: &str = include_str!("fixtures/test-jwt-private.pem");
const INBOUND: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[derive(Debug, Clone, Default)]
struct Captured(Arc<Mutex<Vec<SpanData>>>);

impl SpanExporter for Captured {
    fn export(&mut self, batch: Vec<SpanData>) -> BoxFuture<'static, ExportResult> {
        self.0.lock().unwrap().extend(batch);
        Box::pin(async { Ok(()) })
    }
}

impl Captured {
    fn all(&self) -> Vec<SpanData> {
        self.0.lock().unwrap().clone()
    }
    fn named(&self, name: &str) -> Vec<SpanData> {
        self.all().into_iter().filter(|s| s.name == name).collect()
    }
}

fn attr(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.to_string())
}

/// Thread-local subscriber with the production OTel layer exporting into
/// `Captured`. `#[tokio::test]` runs on the current thread, so the guard
/// covers every request in the test.
fn otel_capture() -> (Captured, TracerProvider, tracing::subscriber::DefaultGuard) {
    observability::set_otel_active_for_tests(true);
    let captured = Captured::default();
    let provider = TracerProvider::builder()
        .with_simple_exporter(captured.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("debug"))
        .with(observability::layer(&provider));
    let guard = tracing::subscriber::set_default(subscriber);
    (captured, provider, guard)
}

async fn setup(provider_base: Option<&str>) -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;
    let pool = db::connect(&db_url, &tim::config::DatabaseConfig::default())
        .await
        .ok()?;
    db::run_migrations(&pool).await.ok()?;
    sqlx::query("TRUNCATE TABLE auth.oauth_state, auth.session")
        .execute(&pool)
        .await
        .ok()?;
    std::env::set_var("OTEL_IT_CLIENT_ID", "tim-client");
    std::env::set_var("OTEL_IT_CLIENT_SECRET", "SECRET-MARKER-c1");
    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    cfg.introspection.required_client_auth = false;
    cfg.server.public_base_url = "https://tim.example.com".into();
    if let Some(base) = provider_base {
        let mut provider = ProviderConfig {
            name: "MockIdP".into(),
            discovery_url: format!("{base}/.well-known/openid-configuration"),
            client_id_env: "OTEL_IT_CLIENT_ID".into(),
            client_secret_env: "OTEL_IT_CLIENT_SECRET".into(),
            scopes: vec!["openid".into()],
            claim_mappings: Default::default(),
            token_validation: TokenValidationConfig::default(),
            allowed_redirect_uris: vec!["https://tim.example.com/auth/callback/mock".into()],
            allow_http_discovery: true,
            jwks_uri: None,
        };
        provider
            .claim_mappings
            .insert("email".into(), "email".into());
        cfg.oauth2.providers.insert("mock".into(), provider);
    }
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "otel-it".into()).ok()?;
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(ProviderRegistry::from_config(&cfg.oauth2).await.ok()?);
    let sessions = Arc::new(MemoryStore::new(Duration::from_secs(3600)));
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

async fn get(
    router: &axum::Router,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Value) {
    let mut b = axum::http::Request::builder().method("GET").uri(path);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let resp = router
        .clone()
        .oneshot(b.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn header(h: &HeaderMap, name: &str) -> String {
    h.get(name)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn request_span_continues_inbound_trace_with_route_pattern() {
    let Some(router) = setup(None).await else {
        return;
    };
    let (captured, provider, guard) = otel_capture();
    let (status, headers, _) = get(
        &router,
        "/auth/providers/PATH-MARKER-1?code=QUERY-MARKER-2",
        &[("traceparent", INBOUND), ("cookie", "COOKIE-MARKER-3")],
    )
    .await;
    drop(guard);
    let _ = provider.force_flush();
    assert_eq!(status, StatusCode::NOT_FOUND);

    let spans = captured.all();
    assert_eq!(spans.len(), 1, "one request span: {spans:?}");
    let span = &spans[0];
    let ctx = &span.span_context;
    assert_eq!(span.name, "GET /auth/providers/:id");
    assert_eq!(span.span_kind, SpanKind::Server);
    assert_eq!(
        ctx.trace_id().to_string(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(span.parent_span_id.to_string(), "00f067aa0ba902b7");
    assert_eq!(
        attr(span, "http.route").as_deref(),
        Some("/auth/providers/:id")
    );
    assert_eq!(
        attr(span, "http.response.status_code").as_deref(),
        Some("404")
    );
    assert_eq!(span.status, Status::Unset, "4xx is not a server error");
    let dump = format!("{} {:?} {:?}", span.name, span.attributes, span.events);
    for marker in ["PATH-MARKER", "QUERY-MARKER", "COOKIE-MARKER", "?"] {
        assert!(!dump.contains(marker), "{marker} leaked: {dump}");
    }
    // Response names the exported span; same trace id as the caller.
    assert_eq!(
        header(&headers, "traceparent"),
        format!("00-{}-{}-01", ctx.trace_id(), ctx.span_id())
    );
    assert_eq!(
        header(&headers, "x-trace-id"),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
}

/// `MakeWriter` collecting fmt output for log assertions.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn access_log_line_names_the_exported_span() {
    let Some(router) = setup(None).await else {
        return;
    };
    observability::set_otel_active_for_tests(true);
    let captured = Captured::default();
    let provider = TracerProvider::builder()
        .with_simple_exporter(captured.clone())
        .build();
    let logs = LogBuf::default();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(logs.clone()),
        )
        .with(observability::layer(&provider));
    let guard = tracing::subscriber::set_default(subscriber);
    let _ = get(&router, "/auth/providers", &[("traceparent", INBOUND)]).await;
    drop(guard);
    let _ = provider.force_flush();

    let span = &captured.named("GET /auth/providers")[0];
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("http_request_completed"))
        .expect("access log line");
    assert!(
        line.contains(&format!("trace_id={}", span.span_context.trace_id()))
            && line.contains(&format!("span_id={}", span.span_context.span_id())),
        "{line}"
    );
}

#[tokio::test]
async fn request_without_or_with_bad_traceparent_is_a_root_matching_headers() {
    let Some(router) = setup(None).await else {
        return;
    };
    let (captured, provider, guard) = otel_capture();
    let (_, plain, _) = get(&router, "/auth/providers", &[]).await;
    let (_, bad, _) = get(&router, "/auth/providers", &[("traceparent", "garbage")]).await;
    let upper = "00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-00";
    let (_, up, _) = get(&router, "/auth/providers", &[("traceparent", upper)]).await;
    drop(guard);
    let _ = provider.force_flush();

    // flags=00 (not sampled) is honoured: that span is not exported, but
    // the response still continues the caller's trace with its flags.
    assert_eq!(
        &header(&up, "traceparent")[..35],
        "00-0af7651916cd43dd8448eb211c80319c"
    );
    assert!(header(&up, "traceparent").ends_with("-00"));
    assert_eq!(
        header(&up, "x-trace-id"),
        "0af7651916cd43dd8448eb211c80319c"
    );

    let spans = captured.named("GET /auth/providers");
    assert_eq!(spans.len(), 2, "{spans:?}");
    for (span, h) in spans.iter().zip([&plain, &bad]) {
        let ctx = &span.span_context;
        assert_eq!(span.parent_span_id, SpanId::INVALID, "root span");
        assert_eq!(header(h, "x-trace-id"), ctx.trace_id().to_string());
        assert_eq!(
            header(h, "traceparent"),
            format!("00-{}-{}-01", ctx.trace_id(), ctx.span_id())
        );
    }
}

#[tokio::test]
async fn health_probes_produce_no_spans() {
    let Some(router) = setup(None).await else {
        return;
    };
    let (captured, provider, guard) = otel_capture();
    for path in ["/health", "/healthz", "/auth/health"] {
        let (_, headers, _) = get(&router, path, &[]).await;
        assert_eq!(header(&headers, "x-trace-id").len(), 32, "{path}");
    }
    drop(guard);
    let _ = provider.force_flush();
    assert!(captured.all().is_empty(), "{:?}", captured.all());
}

fn idp_keypair() -> (RsaPublicKey, String) {
    let sk = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("gen key");
    let pk = RsaPublicKey::from(&sk);
    let pem = sk
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string();
    (pk, pem)
}

/// Full mocked OIDC login: discovery, JWKS and token exchange become
/// CLIENT spans under the callback's SERVER span, the token endpoint
/// receives the client span's `traceparent`, and no OAuth/OIDC secret or
/// personal data reaches any span.
#[tokio::test]
async fn oidc_login_yields_client_spans_without_secrets_or_personal_data() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (pk, pem) = idp_keypair();
    let kid = "idp-kid-otel";
    let discovery = json!({
        "issuer": base.clone(),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
    })
    .to_string();
    let _m_disc = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&discovery)
        .create_async()
        .await;
    let jwk = json!({
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(pk.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(pk.e().to_bytes_be()),
    });
    let _m_jwks = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(json!({ "keys": [jwk] }).to_string())
        .create_async()
        .await;

    let Some(router) = setup(Some(&base)).await else {
        return;
    };
    let (captured, provider, guard) = otel_capture();

    let (s, _, body) = get(&router, "/auth/login/mock", &[]).await;
    assert_eq!(s, StatusCode::OK, "login: {body:?}");
    let state = body["state"].as_str().expect("state").to_string();
    let db_url = std::env::var("TIM_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
    let (nonce,): (String,) = sqlx::query_as("SELECT nonce FROM auth.oauth_state WHERE state = $1")
        .bind(&state)
        .fetch_one(&pool)
        .await
        .unwrap();

    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": base.clone(), "sub": "PERSONAL-MARKER-38001085718", "aud": "tim-client",
        "exp": now + 300, "iat": now, "nonce": nonce, "email": "EMAIL-MARKER@example.com",
    });
    let id_token = {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(kid.into());
        encode(
            &h,
            &claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    };
    let seen_traceparent: Arc<Mutex<Vec<String>>> = Arc::default();
    let token_body = json!({
        "access_token": "ACCESS-MARKER-a1", "id_token": id_token,
        "token_type": "Bearer", "expires_in": 3600,
    })
    .to_string();
    let _m_tok = {
        let seen = seen_traceparent.clone();
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |req| {
                for v in req.header("traceparent") {
                    seen.lock()
                        .unwrap()
                        .push(v.to_str().unwrap_or_default().to_string());
                }
                token_body.clone().into_bytes()
            })
            .create_async()
            .await
    };

    let (s, _, body) = get(
        &router,
        &format!("/auth/callback/mock?code=CODE-MARKER-c2&state={state}"),
        &[("traceparent", INBOUND)],
    )
    .await;
    drop(guard);
    let _ = provider.force_flush();
    assert_eq!(s, StatusCode::OK, "callback: {body:?}");

    let callback = &captured.named("GET /auth/callback/:id")[0];
    assert_eq!(callback.span_kind, SpanKind::Server);
    assert_eq!(
        callback.span_context.trace_id().to_string(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    let token = &captured.named("POST oidc.token")[0];
    assert_eq!(token.span_kind, SpanKind::Client);
    assert_eq!(token.parent_span_id, callback.span_context.span_id());
    assert_eq!(
        token.span_context.trace_id(),
        callback.span_context.trace_id()
    );
    assert_eq!(attr(token, "http.request.method").as_deref(), Some("POST"));
    assert_eq!(
        attr(token, "http.response.status_code").as_deref(),
        Some("200")
    );
    assert_eq!(attr(token, "url.full"), Some(format!("{base}/token")));
    assert_eq!(attr(token, "server.address").as_deref(), Some("127.0.0.1"));
    assert_eq!(token.status, Status::Unset);
    assert_eq!(
        *seen_traceparent.lock().unwrap(),
        vec![format!(
            "00-{}-{}-01",
            token.span_context.trace_id(),
            token.span_context.span_id()
        )],
        "token endpoint receives the client span's traceparent"
    );
    assert!(
        !captured.named("GET oidc.jwks").is_empty(),
        "{:?}",
        captured.all()
    );
    assert!(!captured.named("GET oidc.discovery").is_empty());

    for span in captured.all() {
        let dump = format!("{} {:?}", span.name, span.attributes);
        for marker in [
            "MARKER",
            &state,
            &nonce,
            "tim-client",
            "Basic ",
            "eyJ", // any JWT
            "code=",
            "?",
        ] {
            assert!(!dump.contains(marker), "{marker:?} leaked: {dump}");
        }
        assert!(span.events.is_empty(), "span events: {:?}", span.events);
    }
}

#[tokio::test]
async fn client_span_marks_http_and_transport_errors() {
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/jwks")
        .match_query(mockito::Matcher::Any)
        .with_status(503)
        .create_async()
        .await;
    let (captured, provider, guard) = otel_capture();
    let http = reqwest::Client::new();
    let resp = observability::send(http.get(format!("{}/jwks?x=1", server.url())), "oidc.jwks")
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 503);
    // Closed port: connect error, kind only (no message, no URL).
    let err = observability::send(http.get("http://127.0.0.1:9/token"), "oidc.token")
        .await
        .unwrap_err();
    assert!(err.is_connect() || err.is_request(), "{err}");
    drop(guard);
    let _ = provider.force_flush();

    let jwks = &captured.named("GET oidc.jwks")[0];
    assert!(matches!(jwks.status, Status::Error { .. }));
    assert_eq!(attr(jwks, "error.type").as_deref(), Some("503"));
    assert_eq!(
        attr(jwks, "url.full"),
        Some(format!("{}/jwks", server.url()))
    );
    let token = &captured.named("GET oidc.token")[0];
    assert!(matches!(token.status, Status::Error { .. }));
    assert_eq!(attr(token, "error.type").as_deref(), Some("connect"));
    assert_eq!(attr(token, "server.port").as_deref(), Some("9"));
}

/// Every env-var-driven check lives in this one test: env is process-global
/// and the other tests in this binary run in parallel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exporter_and_resource_follow_otel_env_vars() {
    use observability::{otlp_transport_from_env, OtlpTransport};

    for key in [
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
    ] {
        std::env::remove_var(key);
    }
    assert_eq!(otlp_transport_from_env(), OtlpTransport::Grpc);
    std::env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf");
    assert_eq!(otlp_transport_from_env(), OtlpTransport::HttpProtobuf);
    std::env::set_var("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc");
    assert_eq!(
        otlp_transport_from_env(),
        OtlpTransport::Grpc,
        "per-signal wins"
    );
    std::env::set_var("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/json");
    assert_eq!(
        otlp_transport_from_env(),
        OtlpTransport::Grpc,
        "unsupported -> grpc"
    );
    std::env::remove_var("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL");

    std::env::set_var("OTEL_SERVICE_NAME", "");
    assert_eq!(observability::service_name(), "tim");
    std::env::set_var("OTEL_SERVICE_NAME", "my-identity");
    assert_eq!(observability::service_name(), "my-identity");
    std::env::remove_var("OTEL_SERVICE_NAME");

    std::env::set_var(
        "OTEL_RESOURCE_ATTRIBUTES",
        "deployment.environment=staging,service.namespace=my-system,service.name=ignored",
    );
    let res = observability::otel_resource("my-identity");
    let get = |k: &str| {
        res.get(opentelemetry::Key::new(k.to_string()))
            .map(|v| v.to_string())
    };
    assert_eq!(get("service.name").as_deref(), Some("my-identity"));
    assert_eq!(get("deployment.environment").as_deref(), Some("staging"));
    assert_eq!(get("service.namespace").as_deref(), Some("my-system"));
    assert_eq!(
        get("service.version").as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    std::env::remove_var("OTEL_RESOURCE_ATTRIBUTES");

    std::env::remove_var("OTEL_EXPORTER_OTLP_PROTOCOL");
    std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    assert!(observability::init_provider_from_env().is_none());
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "");
    assert!(observability::init_provider_from_env().is_none());

    std::env::set_var(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "https://collector.example:4317",
    );
    observability::build_span_exporter("https://collector.example:4317")
        .expect("https gRPC exporter builds");

    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("POST", "/v1/traces")
        .match_header("authorization", "Bearer s3cret")
        .match_header("content-type", "application/x-protobuf")
        .with_status(200)
        .create_async()
        .await;
    std::env::set_var("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf");
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", server.url());
    std::env::set_var(
        "OTEL_EXPORTER_OTLP_HEADERS",
        "authorization=Bearer%20s3cret",
    );
    let exporter = observability::build_span_exporter(&server.url()).expect("http exporter");
    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .build();
    {
        use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};
        let mut span = provider.tracer("t").start("probe");
        span.end();
    }
    let flushed = tokio::task::spawn_blocking(move || {
        let r = provider.force_flush();
        let _ = provider.shutdown();
        r
    })
    .await
    .unwrap();
    for r in flushed {
        r.expect("flush");
    }
    for key in [
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_HEADERS",
    ] {
        std::env::remove_var(key);
    }
    mock.assert_async().await;
}
