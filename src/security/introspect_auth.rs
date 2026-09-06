//! Optional client authentication for `POST /introspect` (RFC 7662 §2.1).
//!
//! Behaviour when `introspection.required_client_auth = false` (default):
//!   - Endpoint remains unauthenticated (backwards-compatible).
//!
//! Behaviour when `introspection.required_client_auth = true`:
//!   - Caller MUST send `Authorization: Basic <base64(id:secret)>`.
//!   - `client_id` is compared plaintext against the configured list.
//!   - `client_secret` is compared constant-time against the resolved
//!     secret via `subtle::ConstantTimeEq`.
//!   - Missing header / malformed base64 / unknown id / wrong secret
//!     → `TimError::Unauthorized` (401).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use subtle::ConstantTimeEq;

use crate::config::IntrospectionConfig;
use crate::error::TimError;

#[derive(Clone)]
struct ResolvedClient {
    client_id: String,
    secret: Arc<[u8]>,
}

/// Boot-resolved introspection gate. Shared via `AppState`.
#[derive(Clone, Default)]
pub struct IntrospectionGate {
    required: bool,
    clients: Arc<[ResolvedClient]>,
}

impl IntrospectionGate {
    /// Resolve every configured client_secret_env at startup. Returns
    /// `Err` when `required_client_auth = true` and any referenced env
    /// var is missing — fail-closed rather than boot with a broken
    /// gate.
    pub fn from_config(cfg: &IntrospectionConfig) -> Result<Self, TimError> {
        let mut resolved = Vec::with_capacity(cfg.clients.len());
        for c in &cfg.clients {
            match std::env::var(&c.client_secret_env) {
                Ok(v) if !v.is_empty() => resolved.push(ResolvedClient {
                    client_id: c.client_id.clone(),
                    secret: v.into_bytes().into(),
                }),
                _ if cfg.required_client_auth => {
                    return Err(TimError::Config(format!(
                        "introspection.clients[{}].client_secret_env `{}` is unset or empty",
                        c.client_id, c.client_secret_env
                    )));
                }
                _ => {
                    tracing::warn!(
                        client_id = %c.client_id,
                        env = %c.client_secret_env,
                        "introspection client secret unresolved (skipped)"
                    );
                }
            }
        }
        if cfg.required_client_auth {
            tracing::info!(
                client_count = resolved.len(),
                "introspection client auth ENFORCED"
            );
        }
        Ok(Self {
            required: cfg.required_client_auth,
            clients: resolved.into(),
        })
    }

    pub fn required(&self) -> bool {
        self.required
    }

    /// Verify a Basic auth header value (the raw `Basic <base64>` string
    /// as pulled from the `Authorization` header). Returns `Ok(())` on
    /// a match, `Err(Unauthorized)` otherwise. Never leaks whether the
    /// failure was id-not-found vs. secret-mismatch.
    pub fn verify_basic(&self, header_value: &str) -> Result<(), TimError> {
        let encoded = header_value
            .strip_prefix("Basic ")
            .ok_or(TimError::Unauthorized)?
            .trim();
        let decoded = B64.decode(encoded).map_err(|_| TimError::Unauthorized)?;
        let pair = std::str::from_utf8(&decoded).map_err(|_| TimError::Unauthorized)?;
        let (id, secret) = pair.split_once(':').ok_or(TimError::Unauthorized)?;

        // Walk every configured client so we don't short-circuit on id
        // match — timing-wise this is fine because the list is small,
        // but it also means an attacker cannot enumerate valid ids by
        // response timing (all responses walk the full list).
        let presented_secret = secret.as_bytes();
        let mut any_match = false;
        for c in self.clients.iter() {
            let id_ok = c.client_id.as_bytes() == id.as_bytes();
            let secret_ok =
                c.secret.len() == presented_secret.len() && c.secret.ct_eq(presented_secret).into();
            if id_ok && secret_ok {
                any_match = true;
            }
        }
        if any_match {
            Ok(())
        } else {
            Err(TimError::Unauthorized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IntrospectionClient;

    fn cfg(required: bool, entries: &[(&str, &str)]) -> IntrospectionConfig {
        IntrospectionConfig {
            required_client_auth: required,
            clients: entries
                .iter()
                .map(|(id, env)| IntrospectionClient {
                    client_id: (*id).into(),
                    client_secret_env: (*env).into(),
                })
                .collect(),
        }
    }

    fn basic(pair: &str) -> String {
        format!("Basic {}", B64.encode(pair.as_bytes()))
    }

    #[test]
    fn boot_fails_when_required_and_secret_env_missing() {
        std::env::remove_var("TEST_INTROSPECT_MISSING_1");
        let c = cfg(true, &[("cli", "TEST_INTROSPECT_MISSING_1")]);
        assert!(IntrospectionGate::from_config(&c).is_err());
    }

    #[test]
    fn boot_ok_when_not_required_and_secret_missing() {
        std::env::remove_var("TEST_INTROSPECT_MISSING_2");
        let c = cfg(false, &[("cli", "TEST_INTROSPECT_MISSING_2")]);
        assert!(IntrospectionGate::from_config(&c).is_ok());
    }

    #[test]
    fn verify_accepts_matching_credentials() {
        std::env::set_var("TEST_INTROSPECT_OK", "s3cret");
        let c = cfg(true, &[("caller", "TEST_INTROSPECT_OK")]);
        let g = IntrospectionGate::from_config(&c).unwrap();
        assert!(g.verify_basic(&basic("caller:s3cret")).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        std::env::set_var("TEST_INTROSPECT_BAD", "correct");
        let c = cfg(true, &[("caller", "TEST_INTROSPECT_BAD")]);
        let g = IntrospectionGate::from_config(&c).unwrap();
        assert!(g.verify_basic(&basic("caller:wrong")).is_err());
    }

    #[test]
    fn verify_rejects_unknown_client_id() {
        std::env::set_var("TEST_INTROSPECT_UNK", "s3cret");
        let c = cfg(true, &[("caller", "TEST_INTROSPECT_UNK")]);
        let g = IntrospectionGate::from_config(&c).unwrap();
        assert!(g.verify_basic(&basic("someone-else:s3cret")).is_err());
    }

    #[test]
    fn verify_rejects_bearer_scheme() {
        std::env::set_var("TEST_INTROSPECT_BEARER", "s3cret");
        let c = cfg(true, &[("caller", "TEST_INTROSPECT_BEARER")]);
        let g = IntrospectionGate::from_config(&c).unwrap();
        assert!(g.verify_basic("Bearer caller:s3cret").is_err());
    }

    #[test]
    fn verify_rejects_malformed_base64() {
        std::env::set_var("TEST_INTROSPECT_B64", "s3cret");
        let c = cfg(true, &[("caller", "TEST_INTROSPECT_B64")]);
        let g = IntrospectionGate::from_config(&c).unwrap();
        assert!(g.verify_basic("Basic !!!not-base64!!!").is_err());
    }

    #[test]
    fn verify_rejects_missing_colon() {
        std::env::set_var("TEST_INTROSPECT_COLON", "s3cret");
        let c = cfg(true, &[("caller", "TEST_INTROSPECT_COLON")]);
        let g = IntrospectionGate::from_config(&c).unwrap();
        let no_colon = format!("Basic {}", B64.encode(b"noColonAtAll"));
        assert!(g.verify_basic(&no_colon).is_err());
    }
}
