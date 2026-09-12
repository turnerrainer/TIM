//! Outbound HTTP posture: `TIM_OFFLINE` mode.
//!
//! Fleet-strongholds §9.1 — during pentest engagements / break-tests
//! / adversarial CI runs, TIM must NEVER accidentally reach a real
//! upstream IdP. The XTR audit noted ~40 accidental probes hitting a
//! live Estonian government service during a log-attack pass; TIM's
//! outbound surface is smaller (discovery, JWKS, token exchange) but
//! the same risk class exists whenever a test config carries a
//! production discovery URL.
//!
//! Enable by setting `TIM_OFFLINE=1` (or `true`) at boot. Every
//! outbound call at `src/oauth2/{discovery,jwks,flow}.rs` short-
//! circuits with `TimError::UpstreamTimeout` naming the blocked URL,
//! so tests can assert "outbound was attempted, and blocked" instead
//! of getting silence.
//!
//! Design notes:
//! - Env var, not config field. Reason: a test harness or CI job that
//!   wants to force offline shouldn't have to touch the operator's
//!   `tim.yaml`. Setting `TIM_OFFLINE=1` on the process is the
//!   simplest possible integration.
//! - Value cached in a `OnceLock` at first read. The env var is
//!   evaluated once per process; changing it mid-run has no effect.
//!   This matches the "boot posture" model.

use std::sync::OnceLock;

use crate::error::TimError;

const ENV: &str = "TIM_OFFLINE";
static CACHE: OnceLock<bool> = OnceLock::new();

/// Read `TIM_OFFLINE` from the environment once and cache the result.
/// Accepts `1`, `true`, `TRUE`, `yes` (case-insensitive) as truthy;
/// everything else (including absence, empty string, `0`, `false`)
/// is falsy.
pub fn is_offline() -> bool {
    *CACHE.get_or_init(|| match std::env::var(ENV) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    })
}

/// Emit a boot-time WARN when offline mode is on. Called from
/// `main::serve` after the tracing subscriber is installed.
pub fn diagnose_at_boot() {
    if is_offline() {
        tracing::warn!(
            target: "tim::http",
            env = ENV,
            "TIM_OFFLINE={} — all OIDC discovery / JWKS / token-exchange \
             outbound requests will be refused with 502. Intended for \
             pentest / break-test runs; disable in production.",
            std::env::var(ENV).unwrap_or_default()
        );
    }
}

/// Short-circuit an outbound call. Returns `Some(TimError)` when
/// `TIM_OFFLINE=1`; `None` otherwise. Callers use `?` on the option
/// via `if let Some(e) = block_if_offline("...") { return Err(e); }`.
///
/// URL is included in the error message so operators + test harnesses
/// can see which upstream was blocked. That URL comes from
/// operator-supplied config (never from a request body) so log
/// injection risk is nil.
pub fn block_if_offline(url: &str) -> Option<TimError> {
    if is_offline() {
        tracing::info!(target: "tim::http", url, "TIM_OFFLINE: outbound blocked");
        Some(TimError::UpstreamTimeout(format!(
            "TIM_OFFLINE=1 refuses outbound to `{url}`"
        )))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    // NOTE: `is_offline()` caches the first read. These tests set the
    // env var BEFORE the first call in each binary; because cargo test
    // may reuse the same binary across #[test] fns, we serialise state
    // via distinct env var names in downstream integration tests. Here
    // we only exercise the parser via the matcher shape; the
    // block_if_offline() end-to-end path lives in
    // tests/security_offline_mode.rs (isolated per-binary env).

    #[test]
    fn env_matcher_accepts_truthy_variants() {
        for v in ["1", "true", "TRUE", "True", "yes", "YES"] {
            let parsed = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes");
            assert!(parsed, "`{v}` should be truthy");
        }
    }

    #[test]
    fn env_matcher_rejects_falsy_variants() {
        for v in ["", "0", "false", "no", "off", "2", "abc"] {
            let parsed = matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes");
            assert!(!parsed, "`{v}` should be falsy");
        }
    }
}
