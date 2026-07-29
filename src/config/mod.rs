use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, TimError};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub oauth2: OAuth2Config,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_url_env")]
    pub url_env: String,
    #[serde(default = "default_min_conn")]
    pub min_connections: u32,
    #[serde(default = "default_max_conn")]
    pub max_connections: u32,
    #[serde(default = "default_auto_migrate")]
    pub auto_migrate: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    #[serde(default = "default_private_key_path")]
    pub private_key_path: PathBuf,
    #[serde(default = "default_kid")]
    pub key_id: String,
    #[serde(default = "default_issuer")]
    pub issuer: String,
    #[serde(default)]
    pub audience: AudienceConfig,
    #[serde(default = "default_max_claims_bytes")]
    pub max_claims_bytes: usize,
    #[serde(default = "default_bulk_revoke_max")]
    pub bulk_revoke_max: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AudienceConfig {
    #[serde(default)]
    pub validation_enabled: bool,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default = "default_audience_default")]
    pub default: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OAuth2Config {
    #[serde(default = "default_session_store")]
    pub session_store: String,
    #[serde(default = "default_discovery_ttl")]
    pub discovery_cache_ttl_seconds: u64,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProviderConfig {
    pub name: String,
    pub discovery_url: String,
    pub client_id_env: String,
    pub client_secret_env: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub claim_mappings: HashMap<String, String>,
    #[serde(default)]
    pub token_validation: TokenValidationConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenValidationConfig {
    #[serde(default = "default_clock_skew")]
    pub clock_skew_seconds: u64,
    #[serde(default = "default_validation_cache_ttl")]
    pub cache_ttl_seconds: u64,
}

impl Default for TokenValidationConfig {
    fn default() -> Self {
        Self {
            clock_skew_seconds: default_clock_skew(),
            cache_ttl_seconds: default_validation_cache_ttl(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            max_request_bytes: default_max_request_bytes(),
            request_timeout_seconds: default_request_timeout(),
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url_env: default_db_url_env(),
            min_connections: default_min_conn(),
            max_connections: default_max_conn(),
            auto_migrate: default_auto_migrate(),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            private_key_path: default_private_key_path(),
            key_id: default_kid(),
            issuer: default_issuer(),
            audience: AudienceConfig::default(),
            max_claims_bytes: default_max_claims_bytes(),
            bulk_revoke_max: default_bulk_revoke_max(),
        }
    }
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            session_store: default_session_store(),
            discovery_cache_ttl_seconds: default_discovery_ttl(),
            session_ttl_seconds: default_session_ttl(),
            providers: HashMap::new(),
        }
    }
}

impl AppConfig {
    /// Load config in the standard search order:
    ///   1. Explicit path (from --config or TIM_CONFIG env).
    ///   2. ./tim.yaml or ./tim.yml in current working directory.
    ///   3. Built-in defaults.
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit {
            return Self::from_path(path);
        }
        for candidate in ["tim.yaml", "tim.yml"] {
            let p = Path::new(candidate);
            if p.exists() {
                return Self::from_path(p);
            }
        }
        Ok(Self::default())
    }

    fn from_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| TimError::Config(format!("read {}: {e}", path.display())))?;
        let cfg: AppConfig = serde_yaml_ng::from_str(&raw)
            .map_err(|e| TimError::Config(format!("parse {}: {e}", path.display())))?;
        Ok(cfg)
    }
}

fn default_bind() -> String {
    "0.0.0.0".into()
}
fn default_port() -> u16 {
    8085
}
fn default_max_request_bytes() -> usize {
    1_048_576
}
fn default_request_timeout() -> u64 {
    30
}
fn default_db_url_env() -> String {
    "TIM_DATABASE_URL".into()
}
fn default_min_conn() -> u32 {
    2
}
fn default_max_conn() -> u32 {
    10
}
fn default_auto_migrate() -> bool {
    true
}
fn default_private_key_path() -> PathBuf {
    PathBuf::from("/opt/tim/keys/jwt-private.pem")
}
fn default_kid() -> String {
    "tim-rs-1".into()
}
fn default_issuer() -> String {
    "TIM".into()
}
fn default_audience_default() -> String {
    "tim-service".into()
}
fn default_max_claims_bytes() -> usize {
    32_768
}
fn default_bulk_revoke_max() -> usize {
    100
}
fn default_session_store() -> String {
    "memory".into()
}
fn default_discovery_ttl() -> u64 {
    3600
}
fn default_session_ttl() -> u64 {
    86_400
}
fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}
fn default_clock_skew() -> u64 {
    60
}
fn default_validation_cache_ttl() -> u64 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = AppConfig::default();
        assert_eq!(c.server.port, 8085);
        assert_eq!(c.database.url_env, "TIM_DATABASE_URL");
        assert_eq!(c.jwt.issuer, "TIM");
        assert_eq!(c.oauth2.session_store, "memory");
        assert!(c.oauth2.providers.is_empty());
    }

    #[test]
    fn parses_minimal_yaml() {
        let yaml = r#"
server:
  port: 9000
jwt:
  issuer: "TEST"
"#;
        let c: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(c.server.port, 9000);
        assert_eq!(c.jwt.issuer, "TEST");
        // Defaults preserved.
        assert_eq!(c.server.bind, "0.0.0.0");
        assert_eq!(c.jwt.key_id, "tim-rs-1");
    }

    #[test]
    fn parses_provider_config() {
        let yaml = r#"
oauth2:
  providers:
    google:
      name: "Google"
      discovery_url: "https://accounts.google.com/.well-known/openid-configuration"
      client_id_env: "GOOG_ID"
      client_secret_env: "GOOG_SECRET"
"#;
        let c: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let p = c.oauth2.providers.get("google").unwrap();
        assert_eq!(p.name, "Google");
        assert_eq!(p.scopes.len(), 3);
        assert_eq!(p.token_validation.clock_skew_seconds, 60);
    }
}
