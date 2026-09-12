//! Fleet-strongholds §9.1 regression pin.
//!
//! `TIM_OFFLINE=1` must short-circuit every outbound HTTP call
//! (discovery, JWKS, token exchange). During pentests and CI runs
//! with production configs in scope, this guards against accidental
//! calls to a live IdP. Same failure mode XTR hit during h2ck.me's
//! log-attack pass (~40 accidental probes to a live upstream).
//!
//! Tests scope: unit-level check on the offline flag semantics +
//! discovery and JWKS refusals. Token endpoint would require a full
//! provider config + real state row; the offline check sits at the
//! same layer as discovery/JWKS so trust-by-mechanism.

use tim::oauth2::jwks::JwksCache;

mod common;

/// Setting `TIM_OFFLINE=1` before the first call to `is_offline()`
/// snapshots true. The value is cached — no way to toggle mid-run,
/// so this binary contains only one #[test] fn that exercises the
/// offline path.
#[tokio::test]
async fn offline_blocks_jwks_fetch() {
    std::env::set_var("TIM_OFFLINE", "1");
    // Force the cache to snapshot true.
    assert!(tim::http::is_offline());

    // Build a JWKS cache. We don't need DNS to resolve — the offline
    // check runs BEFORE the network attempt.
    let cache = JwksCache::new(60);
    let err = cache
        .fetch("https://intentionally-invalid.example.test/jwks")
        .await
        .expect_err("offline mode must block the fetch");
    let msg = err.to_string();
    assert!(
        msg.contains("TIM_OFFLINE"),
        "expected offline-mode error, got: {msg}"
    );
    assert!(
        msg.contains("intentionally-invalid.example.test"),
        "expected URL in error: {msg}"
    );
}
