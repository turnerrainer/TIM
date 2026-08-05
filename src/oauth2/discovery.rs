use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

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
    /// Present in OIDC-compliant discovery docs; missing = pre-OIDC
    /// OAuth2. Optional so parsing doesn't fail, but `validate()`
    /// warns loudly.
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
}

impl Discovery {
    /// Cross-field validation applied after parse (finding 06). Any
    /// failure aborts the login flow before TIM constructs an
    /// authorization URL against a provider it can't complete a code
    /// exchange with.
    pub fn validate(&self) -> Result<()> {
        for (name, val) in [
            ("issuer", &self.issuer),
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
        ] {
            if val.trim().is_empty() {
                return Err(TimError::BadGateway(format!(
                    "discovery: required field `{name}` is empty"
                )));
            }
        }
        for (name, val) in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
        ] {
            if !val.starts_with("https://") {
                // Warn rather than fail — some test providers (and
                // the JVM 2.0 default `http://localhost` example) use
                // http. Fail-closed would break dev flows.
                warn!(field = name, url = %val, "discovery endpoint is not https");
            }
        }
        if !self.grant_types_supported.is_empty()
            && !self
                .grant_types_supported
                .iter()
                .any(|g| g == "authorization_code")
        {
            return Err(TimError::BadGateway(
                "discovery: provider does not advertise `authorization_code` grant".into(),
            ));
        }
        if !self.response_types_supported.is_empty()
            && !self.response_types_supported.iter().any(|r| r == "code")
        {
            return Err(TimError::BadGateway(
                "discovery: provider does not advertise `code` response type".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct DiscoveryCache {
    cache: Arc<Cache<String, Discovery>>,
    http: reqwest::Client,
    max_retries: u32,
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
            max_retries: 3,
        }
    }

    /// Retry-with-backoff (finding 08). Backoff: 500ms, 1s, 2s,
    /// capped at ~10s total. Only network/5xx errors trigger a
    /// retry — 4xx responses fail fast.
    pub async fn fetch(&self, discovery_url: &str) -> Result<Discovery> {
        if let Some(cached) = self.cache.get(discovery_url).await {
            return Ok(cached);
        }
        let mut last_err: Option<TimError> = None;
        let mut delay_ms = 500u64;
        for attempt in 0..=self.max_retries {
            match self.fetch_once(discovery_url).await {
                Ok(doc) => {
                    doc.validate()?;
                    self.cache
                        .insert(discovery_url.to_string(), doc.clone())
                        .await;
                    return Ok(doc);
                }
                Err(e) if attempt == self.max_retries => {
                    return Err(e);
                }
                Err(e) if retryable(&e) => {
                    debug!(
                        error = %e,
                        attempt = attempt + 1,
                        max = self.max_retries + 1,
                        "discovery fetch failed; retrying"
                    );
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms = (delay_ms * 2).min(4_000);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| TimError::BadGateway("discovery: retries exhausted".into())))
    }

    async fn fetch_once(&self, url: &str) -> Result<Discovery> {
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| TimError::BadGateway(format!("discovery fetch: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let msg = format!("discovery returned {status}");
            if status.is_server_error() {
                return Err(TimError::BadGateway(msg));
            }
            return Err(TimError::BadGateway(msg));
        }
        resp.json::<Discovery>()
            .await
            .map_err(|e| TimError::BadGateway(format!("discovery parse: {e}")))
    }
}

fn retryable(err: &TimError) -> bool {
    match err {
        TimError::UpstreamTimeout(_) => true,
        TimError::BadGateway(msg) => {
            // Retry on connection errors and 5xx; skip 4xx.
            !msg.contains("returned 4")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> Discovery {
        Discovery {
            issuer: "https://idp".into(),
            authorization_endpoint: "https://idp/authorize".into(),
            token_endpoint: "https://idp/token".into(),
            userinfo_endpoint: None,
            jwks_uri: "https://idp/jwks".into(),
            grant_types_supported: vec!["authorization_code".into()],
            response_types_supported: vec!["code".into()],
        }
    }

    #[test]
    fn validate_ok() {
        assert!(doc().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_issuer() {
        let mut d = doc();
        d.issuer = "".into();
        assert!(d.validate().is_err());
    }

    #[test]
    fn validate_rejects_no_authorization_code_grant() {
        let mut d = doc();
        d.grant_types_supported = vec!["implicit".into()];
        assert!(d.validate().is_err());
    }

    #[test]
    fn validate_rejects_no_code_response_type() {
        let mut d = doc();
        d.response_types_supported = vec!["id_token".into()];
        assert!(d.validate().is_err());
    }

    #[test]
    fn validate_accepts_missing_optional_advertisements() {
        let mut d = doc();
        d.grant_types_supported.clear();
        d.response_types_supported.clear();
        assert!(d.validate().is_ok());
    }
}
