//! Per-request INFO access-log middleware.
//!
//! Audit LOG-v1 FN-LOG-2 — before this, TIM at `RUST_LOG=info` produced
//! zero per-request log lines. The log-attack pass sent 42+ varied probes
//! (200s, 400s, 431s) and got only the boot lines back. That's a SOC2 CC7.2
//! / ISO27001 A.12.4 access-logging compliance gap.
//!
//! This middleware emits exactly one INFO line per completed request:
//!   INFO http_request_completed method=POST route=/introspect
//!        status=200 duration_us=1234 trace_id=<32-char-hex>
//!
//! **trace_id inheritance** — Buerostack topology: Ruuter is the fleet's
//! reverse proxy. Every request TIM sees carries a W3C `traceparent`
//! header set by Ruuter. Extract the 32-char trace-id from it so log
//! entries in Ruuter and TIM can be correlated end-to-end. If missing
//! (direct-hit dev scenario), generate a fresh short id.
//!
//! Deliberate omissions (defense-in-depth privacy):
//! - No headers logged — Authorization etc. never appear
//! - No request/response body logged
//! - No client IP (Ruuter sits in front; the useful IP is in Ruuter's log)
//! - Matched route pattern (`/auth/login/:id`), not raw URI — path
//!   parameters and query string do not enter the log

use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

pub async fn access_log_middleware(req: Request, next: Next) -> Response {
    let start = Instant::now();

    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string());
    let trace_id = extract_trace_id(&req);

    let response = next.run(req).await;

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

    response
}

/// W3C traceparent header format: `00-<32-char-trace-id>-<16-char-span-id>-<flags>`.
/// Extract the trace-id if the incoming header is well-formed. Otherwise
/// generate a fresh 16-char hex id (compact for log noise; full 32 chars
/// would be overkill for local correlation).
fn extract_trace_id(req: &Request) -> String {
    if let Some(tp) = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
    {
        let parts: Vec<&str> = tp.split('-').collect();
        // W3C: 4 parts, hex-only, part 1 is 32-char trace-id
        if parts.len() == 4
            && parts[1].len() == 32
            && parts[1].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return parts[1].to_string();
        }
    }
    // No usable header — generate a fresh short id. TIM already depends
    // on `rand` for OAuth state generation; use the same OsRng.
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request as HttpRequest};

    #[test]
    fn extract_trace_id_from_valid_traceparent() {
        let req = HttpRequest::builder()
            .header(
                "traceparent",
                "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            )
            .body(Body::empty())
            .unwrap();
        let tp = extract_trace_id(&req);
        assert_eq!(tp, "0af7651916cd43dd8448eb211c80319c");
    }

    #[test]
    fn extract_trace_id_generates_fresh_when_header_missing() {
        let req = HttpRequest::builder().body(Body::empty()).unwrap();
        let tp = extract_trace_id(&req);
        assert_eq!(tp.len(), 16, "should be 16 hex chars (8 bytes)");
        assert!(tp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn extract_trace_id_rejects_malformed_traceparent() {
        // Too few parts
        let req = HttpRequest::builder()
            .header("traceparent", "invalid-header")
            .body(Body::empty())
            .unwrap();
        let tp = extract_trace_id(&req);
        assert_eq!(tp.len(), 16, "should fall back to fresh id");

        // Wrong trace-id length
        let req = HttpRequest::builder()
            .header("traceparent", "00-short-b7ad6b7169203331-01")
            .body(Body::empty())
            .unwrap();
        let tp = extract_trace_id(&req);
        assert_eq!(tp.len(), 16, "should fall back to fresh id");

        // Non-hex chars
        let req = HttpRequest::builder()
            .header(
                "traceparent",
                "00-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX-b7ad6b7169203331-01",
            )
            .body(Body::empty())
            .unwrap();
        let tp = extract_trace_id(&req);
        assert_eq!(tp.len(), 16, "should fall back to fresh id");
    }
}
