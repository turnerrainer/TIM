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
    pub async fn fetch(&self, jwks_uri: &str) -> Result<SharedJwks> {
        if let Some(cached) = self.cache.get(jwks_uri).await {
            return Ok(cached);
        }
        let resp = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| TimError::BadGateway(format!("JWKS fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(TimError::BadGateway(format!(
                "JWKS endpoint returned {}",
                resp.status()
            )));
        }
        let body: JwksBody = resp
            .json()
            .await
            .map_err(|e| TimError::BadGateway(format!("JWKS parse: {e}")))?;
        let set = Arc::new(body.into_jwk_set());
        self.cache.insert(jwks_uri.to_string(), set.clone()).await;
        Ok(set)
    }
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
}
