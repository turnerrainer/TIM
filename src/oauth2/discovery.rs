use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde::{Deserialize, Serialize};

use crate::error::{Result, TimError};

/// Subset of the OIDC discovery document TIM cares about.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
}

#[derive(Clone)]
pub struct DiscoveryCache {
    cache: Arc<Cache<String, Discovery>>,
    http: reqwest::Client,
}

impl DiscoveryCache {
    pub fn new(ttl_seconds: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_seconds))
            .max_capacity(64)
            .build();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build reqwest client");
        Self {
            cache: Arc::new(cache),
            http,
        }
    }

    pub async fn fetch(&self, discovery_url: &str) -> Result<Discovery> {
        if let Some(cached) = self.cache.get(discovery_url).await {
            return Ok(cached);
        }
        let resp = self
            .http
            .get(discovery_url)
            .send()
            .await
            .map_err(|e| TimError::BadGateway(format!("discovery fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(TimError::BadGateway(format!(
                "discovery returned {}",
                resp.status()
            )));
        }
        let doc: Discovery = resp
            .json()
            .await
            .map_err(|e| TimError::BadGateway(format!("discovery parse: {e}")))?;
        self.cache
            .insert(discovery_url.to_string(), doc.clone())
            .await;
        Ok(doc)
    }
}
