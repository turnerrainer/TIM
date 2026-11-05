//! Optional OpenTelemetry trace export over OTLP.
//!
//! Export is off unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set. With it off,
//! the request path creates no spans and log output is unchanged. With it on:
//!
//! - every request except health probes becomes a SERVER span parented on
//!   the inbound W3C `traceparent` (see `access_log::access_log_middleware`);
//! - every outbound OIDC call (discovery, JWKS, token exchange) becomes a
//!   CLIENT span and carries its `traceparent` (see [`send`]);
//! - only TIM's own spans are exported. Log events and spans from
//!   dependencies (e.g. `tower_http` request spans, which carry the raw
//!   URI with query string) are filtered out of the export.
//!
//! Environment contract (standard OTel variables):
//!
//! | Variable | Effect |
//! |---|---|
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` | Enables export. gRPC: `http://host:4317`; HTTP: `http(s)://host:4318` |
//! | `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` / `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` (default) or `http/protobuf` |
//! | `OTEL_EXPORTER_OTLP_HEADERS` | Extra exporter headers, e.g. `authorization=Bearer%20<token>` |
//! | `OTEL_EXPORTER_OTLP_TIMEOUT` | Export timeout in ms |
//! | `OTEL_SERVICE_NAME` | `service.name` (default `tim`) |
//! | `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes |
//!
//! Reference: `book/src/observability.md`.

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::{TraceContextExt, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    propagation::TraceContextPropagator, runtime::Tokio, trace::TracerProvider, Resource,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::Layer;

/// Default `service.name` when `OTEL_SERVICE_NAME` is unset.
pub const SERVICE_NAME_DEFAULT: &str = "tim";

/// Set once [`init_provider_from_env`] has wired an exporter. When it is
/// `false` no request or client spans are created, so log output is
/// unchanged.
static OTEL_ACTIVE: AtomicBool = AtomicBool::new(false);

/// `true` when spans are exported over OTLP.
pub fn otel_active() -> bool {
    OTEL_ACTIVE.load(Ordering::Relaxed)
}

/// Test hook: integration tests install their own subscriber with an
/// in-memory exporter and flip this on, instead of going through
/// [`init_provider_from_env`].
#[doc(hidden)]
pub fn set_otel_active_for_tests(active: bool) {
    OTEL_ACTIVE.store(active, Ordering::Relaxed);
}

/// OTLP transport selected by `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` /
/// `OTEL_EXPORTER_OTLP_PROTOCOL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpTransport {
    /// OTLP/gRPC (default, port 4317). Plaintext only.
    Grpc,
    /// OTLP/HTTP with protobuf payloads (port 4318, `<endpoint>/v1/traces`).
    HttpProtobuf,
}

/// Resolve the OTLP transport from the standard env vars. The per-signal
/// variable wins. Unknown values fall back to gRPC with a warning on stderr
/// (the subscriber is not installed yet when this runs).
pub fn otlp_transport_from_env() -> OtlpTransport {
    let raw = std::env::var("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
        .or_else(|_| std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL"))
        .unwrap_or_default();
    match raw.trim() {
        "" | "grpc" => OtlpTransport::Grpc,
        "http/protobuf" => OtlpTransport::HttpProtobuf,
        other => {
            eprintln!(
                "OTEL_EXPORTER_OTLP_PROTOCOL={other:?} is not supported (grpc, http/protobuf); using grpc"
            );
            OtlpTransport::Grpc
        }
    }
}

/// Resource for exported spans: the SDK defaults (which include
/// `OTEL_RESOURCE_ATTRIBUTES` via the env detector) merged with
/// `service.name` / `service.version` from this process, which win.
pub fn otel_resource(service_name: &str) -> Resource {
    Resource::default().merge(&Resource::new(vec![
        KeyValue::new("service.name", service_name.to_string()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ]))
}

/// Build the OTLP span exporter for `endpoint` with the transport from
/// [`otlp_transport_from_env`].
///
/// TLS is provided by OTLP/HTTP through TIM's `reqwest` client (native
/// TLS, system trust store); the gRPC exporter is plaintext. An `https://`
/// endpoint with gRPC therefore warns once and is expected to fail on
/// export.
pub fn build_span_exporter(endpoint: &str) -> Result<opentelemetry_otlp::SpanExporter, String> {
    // Endpoint, OTEL_EXPORTER_OTLP_HEADERS and OTEL_EXPORTER_OTLP_TIMEOUT are
    // read by opentelemetry-otlp itself; header values are never logged here.
    match otlp_transport_from_env() {
        OtlpTransport::Grpc => {
            if endpoint.starts_with("https://") {
                eprintln!(
                    "OTEL_EXPORTER_OTLP_ENDPOINT is https:// but the gRPC exporter has no TLS; \
                     set OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf for a TLS endpoint"
                );
            }
            opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()
                .map_err(|e| e.to_string())
        }
        OtlpTransport::HttpProtobuf => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_endpoint(endpoint)
            .with_http_client(reqwest::Client::new())
            .build()
            .map_err(|e| e.to_string()),
    }
}

/// Build the tracer provider when `OTEL_EXPORTER_OTLP_ENDPOINT` is set and
/// non-empty. Returns `None` (export off) when it is unset or the exporter
/// cannot be built; the latter warns once on stderr and TIM keeps running
/// with local logging only. Must run inside a Tokio runtime.
pub fn init_provider_from_env() -> Option<TracerProvider> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .ok()
        .filter(|s| !s.trim().is_empty())?;
    let exporter = match build_span_exporter(&endpoint) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("OTel exporter init failed ({err}); falling back to local logging only");
            return None;
        }
    };
    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());
    let provider = TracerProvider::builder()
        .with_batch_exporter(exporter, Tokio)
        .with_resource(otel_resource(&service_name()))
        .build();
    OTEL_ACTIVE.store(true, Ordering::Relaxed);
    Some(provider)
}

/// `OTEL_SERVICE_NAME`, or [`SERVICE_NAME_DEFAULT`].
pub fn service_name() -> String {
    std::env::var("OTEL_SERVICE_NAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| SERVICE_NAME_DEFAULT.to_string())
}

/// `true` for metadata TIM itself emits (`tim` or `tim::…` targets).
fn is_own_target(target: &str) -> bool {
    target == "tim" || target.starts_with("tim::")
}

/// The `tracing` layer that exports spans through `provider`.
///
/// Only TIM's own spans pass. Events are filtered out so log lines never
/// become span events, and dependency spans (`tower_http`, `hyper`, `h2`,
/// the exporter's own transport) are not exported.
pub fn layer<S>(provider: &TracerProvider) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(env!("CARGO_PKG_NAME")))
        .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
            meta.is_span() && is_own_target(meta.target())
        }))
}

/// Flush pending spans and stop the exporter.
pub fn shutdown(provider: Option<TracerProvider>) {
    if let Some(p) = provider {
        let _ = p.shutdown();
    }
}

/// Make `span` a child of the remote context carried by a W3C
/// `traceparent` value. Invalid values leave the span as a new root.
pub fn set_parent_from_traceparent(span: &tracing::Span, traceparent: &str) {
    let mut carrier = HashMap::new();
    carrier.insert("traceparent".to_string(), traceparent.to_string());
    let cx = TraceContextPropagator::new().extract(&carrier);
    if cx.span().span_context().is_valid() {
        span.set_parent(cx);
    }
}

/// `(trace_id, span_id, flags)` of `span` as lowercase hex, or `None` when
/// no OTel layer recorded it.
pub fn span_ids(span: &tracing::Span) -> Option<(String, String, String)> {
    let cx = span.context();
    let sc = cx.span().span_context().clone();
    if !sc.is_valid() {
        return None;
    }
    Some((
        sc.trace_id().to_string(),
        sc.span_id().to_string(),
        format!("{:02x}", sc.trace_flags().to_u8()),
    ))
}

/// `scheme://host[:port]/path` of `url`: no userinfo, query or fragment.
pub fn url_without_query(url: &reqwest::Url) -> String {
    let mut out = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        out.push_str(&format!(":{port}"));
    }
    out.push_str(url.path());
    out
}

/// Error kind for a failed outbound call. Never the error message: it can
/// carry the full URL.
fn reqwest_error_type(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_body() || e.is_decode() {
        "body"
    } else if e.is_builder() {
        "builder"
    } else {
        "request"
    }
}

/// Send an outbound request.
///
/// With export off this is exactly `request.send()`. With export on, the
/// call runs inside a CLIENT span named `"{METHOD} {operation}"` (child of
/// the current span) and carries that span's `traceparent` unless the
/// request already has one. Attributes: `http.request.method`,
/// `server.address`, `server.port`, `url.full` (without query string or
/// fragment), `http.response.status_code`, and `error.type` on failure.
/// Request and response headers and bodies are never recorded.
pub async fn send(
    request: reqwest::RequestBuilder,
    operation: &'static str,
) -> reqwest::Result<reqwest::Response> {
    if !otel_active() {
        return request.send().await;
    }
    let (client, request) = request.build_split();
    let mut request = request?;
    let url = request.url().clone();
    let method = request.method().as_str().to_string();
    let span = tracing::info_span!(
        "http_client",
        otel.name = %format!("{method} {operation}"),
        otel.kind = "client",
        otel.status_code = tracing::field::Empty,
        http.request.method = %method,
        server.address = %url.host_str().unwrap_or_default(),
        server.port = url.port_or_known_default().unwrap_or_default(),
        url.full = %url_without_query(&url),
        http.response.status_code = tracing::field::Empty,
        "error.type" = tracing::field::Empty,
        tim.operation = operation,
    );
    if !request.headers().contains_key("traceparent") {
        if let Some((trace, span_id, flags)) = span_ids(&span) {
            if let Ok(v) =
                reqwest::header::HeaderValue::from_str(&format!("00-{trace}-{span_id}-{flags}"))
            {
                request.headers_mut().insert("traceparent", v);
            }
        }
    }
    let result = client.execute(request).instrument(span.clone()).await;
    match &result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            span.record("http.response.status_code", status);
            // Client spans: 4xx and 5xx are errors (OTel HTTP conventions).
            if status >= 400 {
                span.record("otel.status_code", "ERROR");
                span.record("error.type", status.to_string());
            }
        }
        Err(e) => {
            span.record("otel.status_code", "ERROR");
            span.record("error.type", reqwest_error_type(e));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_without_query_drops_userinfo_query_and_fragment() {
        let u = reqwest::Url::parse("https://user:pw@idp.example:8443/oidc/token?code=x&state=y#f")
            .unwrap();
        assert_eq!(url_without_query(&u), "https://idp.example:8443/oidc/token");
        let u =
            reqwest::Url::parse("https://idp.example/.well-known/openid-configuration").unwrap();
        assert_eq!(
            url_without_query(&u),
            "https://idp.example/.well-known/openid-configuration"
        );
    }

    #[test]
    fn own_target_matches_tim_modules_only() {
        assert!(is_own_target("tim"));
        assert!(is_own_target("tim::access_log"));
        assert!(!is_own_target("tower_http::trace::make_span"));
        assert!(!is_own_target("timely"));
    }
}
