use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::config::{OAuth2Config, ProviderConfig};
use crate::error::{Result, TimError};
use crate::oauth2::discovery::DiscoveryCache;
use crate::oauth2::jwks::JwksCache;

/// A fully-resolved provider — config + resolved secrets.
#[derive(Clone)]
pub struct Provider {
    pub id: String,
    pub config: ProviderConfig,
    pub client_id: Arc<str>,
    pub client_secret: Arc<str>,
}

#[derive(Serialize)]
pub struct ProviderPublicInfo {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub claim_mappings: HashMap<String, String>,
}

pub struct ProviderRegistry {
    providers: HashMap<String, Provider>,
    pub discovery: DiscoveryCache,
    pub jwks: JwksCache,
}

impl ProviderRegistry {
    pub async fn from_config(cfg: &OAuth2Config) -> Result<Self> {
        let mut providers = HashMap::new();
        // The per-provider JWKS cache TTL is used to size the shared
        // JWKS cache; pick the max, floor 60 s.
        let mut jwks_ttl = 60u64;
        for (id, pc) in &cfg.providers {
            let client_id = std::env::var(&pc.client_id_env).map_err(|_| {
                TimError::Config(format!(
                    "provider {id}: env var {} not set",
                    pc.client_id_env
                ))
            })?;
            let client_secret = std::env::var(&pc.client_secret_env).map_err(|_| {
                TimError::Config(format!(
                    "provider {id}: env var {} not set",
                    pc.client_secret_env
                ))
            })?;
            jwks_ttl = jwks_ttl.max(pc.token_validation.cache_ttl_seconds);
            providers.insert(
                id.clone(),
                Provider {
                    id: id.clone(),
                    config: pc.clone(),
                    client_id: client_id.into(),
                    client_secret: client_secret.into(),
                },
            );
        }
        Ok(Self {
            providers,
            discovery: DiscoveryCache::new(cfg.discovery_cache_ttl_seconds),
            jwks: JwksCache::new(jwks_ttl),
        })
    }

    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.providers.get(id)
    }

    pub fn list_public(&self) -> Vec<ProviderPublicInfo> {
        self.providers
            .values()
            .map(|p| ProviderPublicInfo {
                id: p.id.clone(),
                name: p.config.name.clone(),
                scopes: p.config.scopes.clone(),
                claim_mappings: p.config.claim_mappings.clone(),
            })
            .collect()
    }

    pub fn ids(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }
}
