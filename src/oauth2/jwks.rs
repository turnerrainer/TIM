//! JWKS fetch + cache used by ID-token verification.
//!
//! Each provider gets its own `moka` cache entry keyed by `jwks_uri`.
//! TTL comes from the per-provider `token_validation.cache_ttl_seconds`
//! (defaulted to 3600 s in `config::TokenValidationConfig`).

use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::jwk::JwkSet;
use moka::future::Cache;
use serde::Deserialize;

use crate::error::{Result, TimError};

/// Newtype so the trait bound on the cache is a nominal type — moka
/// requires `Send + Sync + 'static`; wrapping in `Arc` lets us clone
/// cheaply.
type SharedJwks = Arc<JwkSet>;

#[derive(Clone)]
pub struct JwksCache {
    cache: Arc<Cache<String, SharedJwks>>,
    http: reqwest::Client,
}

impl JwksCache {
    /// `default_ttl_seconds` is a floor; per-provider TTL can extend
    /// it via `token_validation.cache_ttl_seconds` if greater. We keep
    /// a single cache instance for the process — different providers
    /// live in different cache entries.
    pub fn new(default_ttl_seconds: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(default_ttl_seconds.max(1)))
            .max_capacity(64)
            .build();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build reqwest client for JWKS");
        Self {
            cache: Arc::new(cache),
            http,
        }
    }

    /// Fetch (or return cached) JWKS. Errors on any network / parse
    /// problem — the caller (`idtoken::verify`) will refuse the token
    /// rather than proceed without validation.
    ///
    /// Single-flight: concurrent misses on the same `jwks_uri` share
    /// one upstream request via Moka's `try_get_with`. Prevents the
    /// thundering-herd shape where N parallel token verifications after
    /// a cache eviction all hammer the JWKS endpoint (2026-09-17
    /// concurrency mini-audit R-3).
    pub async fn fetch(&self, jwks_uri: &str) -> Result<SharedJwks> {
        let http = self.http.clone();
        let uri = jwks_uri.to_string();
        self.cache
            .try_get_with(uri.clone(), async move { load(&http, &uri).await })
            .await
            .map_err(LoaderErr::into_tim_error)
    }
}

/// The error type surfaced by the single-flight loader. Wrapping in an
/// enum (rather than collapsing to `String`) preserves the distinction
/// between `TIM_OFFLINE` refusals (mapped to `UpstreamTimeout`, gateway-
/// timeout status) and upstream failures (`BadGateway`). Moka returns
/// `Arc<E>` from `try_get_with`, so `E` cannot be `TimError` directly
/// (`TimError` is not `Clone`); the intermediate enum lets us round-trip
/// the variant losslessly.
#[derive(Debug)]
enum LoaderErr {
    Offline(String),
    BadGateway(String),
}

impl LoaderErr {
    fn into_tim_error(arc: Arc<Self>) -> TimError {
        match &*arc {
            LoaderErr::Offline(msg) => TimError::UpstreamTimeout(msg.clone()),
            LoaderErr::BadGateway(msg) => TimError::BadGateway(msg.clone()),
        }
    }
}

/// Perform the actual JWKS fetch. Called exactly once per single-flight
/// group under `try_get_with`; concurrent misses share this future.
async fn load(
    http: &reqwest::Client,
    jwks_uri: &str,
) -> std::result::Result<SharedJwks, LoaderErr> {
    // Fleet §9.1: TIM_OFFLINE=1 short-circuits every outbound.
    if let Some(TimError::UpstreamTimeout(msg)) = crate::http::block_if_offline(jwks_uri) {
        return Err(LoaderErr::Offline(msg));
    }
    let resp = http
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| LoaderErr::BadGateway(format!("JWKS fetch: {e}")))?;
    if !resp.status().is_success() {
        return Err(LoaderErr::BadGateway(format!(
            "JWKS endpoint returned {}",
            resp.status()
        )));
    }
    let body: JwksBody = resp
        .json()
        .await
        .map_err(|e| LoaderErr::BadGateway(format!("JWKS parse: {e}")))?;
    Ok(Arc::new(body.into_jwk_set()))
}

/// We deserialise via a minimal owned wrapper because `jsonwebtoken`'s
/// `JwkSet` re-exports serde derives whose lifetimes force us to hand
/// it owned JSON up front. Doing the round-trip here isolates the
/// dependency's serde quirks.
#[derive(Debug, Deserialize)]
struct JwksBody {
    #[serde(default)]
    keys: Vec<serde_json::Value>,
}

impl JwksBody {
    fn into_jwk_set(self) -> JwkSet {
        let json = serde_json::json!({ "keys": self.keys });
        serde_json::from_value(json).unwrap_or(JwkSet { keys: vec![] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_bad_gateway_on_404() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/jwks")
            .with_status(404)
            .create_async()
            .await;
        let cache = JwksCache::new(60);
        let err = cache
            .fetch(&format!("{}/jwks", server.url()))
            .await
            .unwrap_err();
        assert!(matches!(err, TimError::BadGateway(_)));
        m.assert_async().await;
    }

    #[tokio::test]
    async fn parses_jwks_body() {
        let mut server = mockito::Server::new_async().await;
        let body = r#"{"keys":[{"kty":"RSA","kid":"k1","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}]}"#;
        let m = server
            .mock("GET", "/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;
        let cache = JwksCache::new(60);
        let set = cache
            .fetch(&format!("{}/jwks", server.url()))
            .await
            .unwrap();
        assert_eq!(set.keys.len(), 1);
        m.assert_async().await;
    }

    #[tokio::test]
    async fn caches_on_second_call() {
        let mut server = mockito::Server::new_async().await;
        let body = r#"{"keys":[]}"#;
        let m = server
            .mock("GET", "/jwks")
            .with_status(200)
            .with_body(body)
            // exactly one HTTP call, second should hit cache
            .expect(1)
            .create_async()
            .await;
        let cache = JwksCache::new(60);
        let url = format!("{}/jwks", server.url());
        let _ = cache.fetch(&url).await.unwrap();
        let _ = cache.fetch(&url).await.unwrap();
        m.assert_async().await;
    }

    /// 2026-09-17 concurrency mini-audit R-3 regression pin.
    ///
    /// N concurrent misses on the same `jwks_uri` must coalesce to
    /// exactly one upstream fetch. The previous `get()` + `insert()`
    /// pattern raced: two tasks could each observe a cache miss, each
    /// fetch, and the second `insert()` would overwrite the first —
    /// wasting the upstream call and burning rate-limit budget.
    #[tokio::test]
    async fn concurrent_misses_coalesce_to_single_upstream_fetch() {
        let mut server = mockito::Server::new_async().await;
        // Introduce artificial latency so all 100 tasks are guaranteed
        // to hit the same in-flight window; without it, a fast local
        // mock might complete before the second task's `get()` lands.
        let body =
            r#"{"keys":[{"kty":"RSA","kid":"k","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}]}"#;
        let m = server
            .mock("GET", "/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .with_chunked_body(move |w| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                w.write_all(body.as_bytes())
            })
            // The whole point: exactly one upstream call for N callers.
            .expect(1)
            .create_async()
            .await;

        let cache = JwksCache::new(60);
        let url = format!("{}/jwks", server.url());

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let c = cache.clone();
            let u = url.clone();
            set.spawn(async move { c.fetch(&u).await });
        }
        let mut ok = 0usize;
        while let Some(res) = set.join_next().await {
            let inner = res.expect("join");
            let jwks = inner.expect("fetch");
            assert_eq!(jwks.keys.len(), 1);
            ok += 1;
        }
        assert_eq!(ok, 100, "all callers must receive the same JWKS");
        m.assert_async().await;
    }
}
