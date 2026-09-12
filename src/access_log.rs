//! Per-request INFO access-log middleware + W3C Trace Context response
//! headers.
//!
//! Audit LOG-v1 FN-LOG-2 — before this, TIM at `RUST_LOG=info` produced
//! zero per-request log lines. The log-attack pass sent 42+ varied probes
//! (200s, 400s, 431s) and got only the boot lines back. That's a SOC2 CC7.2
//! / ISO27001 A.12.4 access-logging compliance gap.
//!
//! Fleet-strongholds §1.6 — TIM propagates the W3C Trace Context on the
//! response (`traceparent` + `x-trace-id`) so cross-service correlation
//! works even when the caller can only see TIM's response, not TIM's
//! internal logs. Ruuter is the only other Buerostack service currently
//! doing this.
//!
//! One INFO line per completed request:
//!
//!   INFO http_request_completed method=POST route=/introspect
//!        status=200 duration_us=1234 trace_id=<32-hex>
//!
//! **trace_id inheritance** — Buerostack topology: Ruuter is the fleet's
//! reverse proxy. Every request TIM sees carries a W3C `traceparent`
//! header set by Ruuter. Extract the 32-char trace-id from it so log
//! entries in Ruuter and TIM can be correlated end-to-end. If missing
//! (direct-hit dev scenario), generate a fresh 32-char id.
//!
//! **span_id** — TIM generates a fresh 16-char span_id per request. The
//! outgoing `traceparent` names TIM's span, letting downstream tooling
//! link "the caller's log line about TIM" with "TIM's log line about
//! this request."
//!
//! Deliberate omissions (defense-in-depth privacy):
//! - No headers logged — Authorization etc. never appear
//! - No request/response body logged
//! - No client IP (Ruuter sits in front; the useful IP is in Ruuter's log)
//! - Matched route pattern (`/auth/login/:id`), not raw URI — path
//!   parameters and query string do not enter the log

use axum::extract::{MatchedPath, Request};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

/// Header name for the compact trace-id echo — useful for clients
/// that don't parse the full W3C `traceparent`.
const X_TRACE_ID: &str = "x-trace-id";

pub async fn access_log_middleware(req: Request, next: Next) -> Response {
    let start = Instant::now();

    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());
    let (trace_id, flags) = parse_or_generate_trace_id(&req);
    let span_id = fresh_span_id();

    let mut response = next.run(req).await;

    let status = response.status().as_u16();
    let duration_us = start.elapsed().as_micros();

    tracing::info!(
        method = %method,
        route = %route,
        status,
        duration_us,
        trace_id = %trace_id,
        "http_request_completed"
    );

    // Attach W3C Trace Context on the response. `traceparent` is the
    // full spec form; `x-trace-id` is a convenience echo for tooling
    // that doesn't parse the composite. Both use HeaderValue::from_str
    // — every field is ASCII-hex (trace_id, span_id, flags) so a
    // parser failure would indicate a bug in our own generator, not
    // an operator misconfig; log-and-drop the header instead of
    // failing the response.
    let traceparent = format!("00-{trace_id}-{span_id}-{flags}");
    match HeaderValue::from_str(&traceparent) {
        Ok(v) => {
            response.headers_mut().insert("traceparent", v);
        }
        Err(e) => {
            tracing::warn!(error = %e, traceparent, "traceparent HeaderValue rejected");
        }
    }
    match HeaderValue::from_str(&trace_id) {
        Ok(v) => {
            response.headers_mut().insert(X_TRACE_ID, v);
        }
        Err(e) => {
            tracing::warn!(error = %e, trace_id, "x-trace-id HeaderValue rejected");
        }
    }

    response
}

/// W3C traceparent header format: `<version>-<32-char-trace-id>-<16-char-span-id>-<flags>`.
///
/// Returns `(trace_id, flags)`:
/// - `trace_id` is 32 lowercase hex chars — inherited from a valid
///   incoming header, or freshly generated from 16 random bytes.
/// - `flags` is 2 lowercase hex chars — inherited when the incoming
///   header was well-formed (preserves the caller's sampling
///   decision), otherwise `"01"` (sampled).
///
/// A malformed header is treated as absent — we do not attempt to
/// repair it or copy partial values.
fn parse_or_generate_trace_id(req: &Request) -> (String, String) {
    if let Some(tp) = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
    {
        let parts: Vec<&str> = tp.split('-').collect();
        // W3C: 4 parts, version=00, trace-id=32 hex, span-id=16 hex,
        // flags=2 hex. Reject `00000...0` trace-id (§3.2.2.4: "If the
        // trace-id value is invalid ... vendors MUST ... generate a
        // new trace-id.") and same for span-id.
        if parts.len() == 4
            && parts[0] == "00"
            && parts[1].len() == 32
            && parts[1].bytes().all(|b| b.is_ascii_hexdigit())
            && parts[1] != "00000000000000000000000000000000"
            && parts[2].len() == 16
            && parts[2].bytes().all(|b| b.is_ascii_hexdigit())
            && parts[3].len() == 2
            && parts[3].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return (parts[1].to_lowercase(), parts[3].to_lowercase());
        }
    }
    // Fresh 16 random bytes → 32 hex chars. Sampled flag on.
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    (
        bytes.iter().map(|b| format!("{b:02x}")).collect(),
        "01".to_string(),
    )
}

/// Generate a fresh 16-char hex span-id (8 random bytes). Called once
/// per request — this is TIM's own span within the (possibly-inherited)
/// trace.
fn fresh_span_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request as HttpRequest};

    #[test]
    fn parse_valid_traceparent_preserves_trace_id_and_flags() {
        let req = HttpRequest::builder()
            .header(
                "traceparent",
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            )
            .body(Body::empty())
            .unwrap();
        let (trace, flags) = parse_or_generate_trace_id(&req);
        assert_eq!(trace, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(flags, "01");
    }

    #[test]
    fn parse_preserves_unsampled_flag() {
        // flags=00 means "not sampled" — must be preserved verbatim so
        // downstream tooling can honour the caller's sampling decision.
        let req = HttpRequest::builder()
            .header(
                "traceparent",
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00",
            )
            .body(Body::empty())
            .unwrap();
        let (_, flags) = parse_or_generate_trace_id(&req);
        assert_eq!(flags, "00");
    }

    #[test]
    fn generate_fresh_when_header_missing() {
        let req = HttpRequest::builder().body(Body::empty()).unwrap();
        let (trace, flags) = parse_or_generate_trace_id(&req);
        assert_eq!(trace.len(), 32, "should be 32 hex chars (16 bytes)");
        assert!(trace.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(flags, "01", "fresh generation defaults to sampled");
    }

    #[test]
    fn generate_fresh_when_header_malformed() {
        // Every axis of malformed input falls back to a fresh trace_id.
        for bad in &[
            "invalid-header",                                          // too few parts
            "00-short-b7ad6b7169203331-01",                            // wrong trace-id len
            "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", // wrong version
            "00-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX-b7ad6b7169203331-01", // non-hex trace-id
            "00-0af7651916cd43dd8448eb211c80319c-short-01",            // wrong span-id len
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-1",  // wrong flags len
            "00-00000000000000000000000000000000-b7ad6b7169203331-01", // invalid all-zero
        ] {
            let req = HttpRequest::builder()
                .header("traceparent", *bad)
                .body(Body::empty())
                .unwrap();
            let (trace, flags) = parse_or_generate_trace_id(&req);
            assert_eq!(trace.len(), 32, "bad={bad}");
            assert_eq!(flags, "01", "bad={bad}");
        }
    }

    #[test]
    fn span_id_is_16_hex_chars_and_random() {
        let a = fresh_span_id();
        let b = fresh_span_id();
        assert_eq!(a.len(), 16);
        assert_eq!(b.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(b.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two consecutive span-ids collided — RNG broken?");
    }

    #[test]
    fn header_case_folding() {
        // W3C: trace-id / span-id / flags are lowercase hex. The
        // parser accepts uppercase input but emits lowercase.
        let req = HttpRequest::builder()
            .header(
                "traceparent",
                "00-0AF7651916CD43DD8448EB211C80319C-B7AD6B7169203331-01",
            )
            .body(Body::empty())
            .unwrap();
        let (trace, _) = parse_or_generate_trace_id(&req);
        assert_eq!(trace, "0af7651916cd43dd8448eb211c80319c");
    }
}
