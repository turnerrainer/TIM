//! Admin-token gate for privileged endpoints.
//!
//! Config:
//!   security.admin_token_env: "TIM_ADMIN_TOKEN"
//!   security.require_admin_token: true
//!
//! Behaviour when the env var is set:
//!   - `AdminAuth` extractor requires `X-TIM-Admin-Token: <secret>`
//!     OR `Authorization: Bearer <secret>` on every gated request.
//!   - Comparison is constant-time.
//!
//! Behaviour when the env var is NOT set:
//!   - If `require_admin_token = true` (default), startup refuses.
//!   - If `require_admin_token = false`, startup emits a WARN log
//!     and the extractor becomes a no-op — used only in tests and
//!     explicit dev environments.

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use subtle::ConstantTimeEq;

use crate::config::SecurityConfig;
use crate::error::TimError;

/// Cheaply-cloneable wrapper around the resolved admin token (if any)
/// so handlers can inspect the gate state without touching env vars
/// at request time.
#[derive(Clone, Default)]
pub struct AdminGate {
    token: Option<Arc<[u8]>>,
}

impl AdminGate {
    /// Resolve the token at startup. Returns `Err` when
    /// `require_admin_token = true` but the env var is unset or
    /// empty.
    pub fn from_config(cfg: &SecurityConfig) -> Result<Self, TimError> {
        if cfg.admin_token_env.is_empty() {
            if cfg.require_admin_token {
                return Err(TimError::Config(
                    "security.admin_token_env is empty but require_admin_token = true; \
                     set the env var name (see security-hardening.md)"
                        .into(),
                ));
            }
            tracing::warn!(
                "security.admin_token_env is empty AND require_admin_token = false — \
                 privileged endpoints are UNGATED. Do not deploy to production."
            );
            return Ok(Self { token: None });
        }
        let raw = std::env::var(&cfg.admin_token_env);
        match raw {
            Ok(val) if !val.is_empty() => Ok(Self {
                token: Some(val.into_bytes().into()),
            }),
            _ if cfg.require_admin_token => Err(TimError::Config(format!(
                "security.admin_token_env `{}` is not set or empty",
                cfg.admin_token_env
            ))),
            _ => {
                tracing::warn!(
                    "security.admin_token_env `{}` is unset — privileged endpoints ungated",
                    cfg.admin_token_env
                );
                Ok(Self { token: None })
            }
        }
    }

    /// True when a token was configured.
    pub fn enforced(&self) -> bool {
        self.token.is_some()
    }

    fn verify(&self, presented: &[u8]) -> bool {
        match &self.token {
            None => true,
            Some(t) => t.len() == presented.len() && t.ct_eq(presented).into(),
        }
    }
}

/// Extractor for privileged endpoints. Returns 401 unless the caller
/// presents the configured token via `X-TIM-Admin-Token:` or
/// `Authorization: Bearer <token>`.
pub struct AdminAuth;

#[axum::async_trait]
impl<S> FromRequestParts<S> for AdminAuth
where
    S: Send + Sync,
    AdminGate: axum::extract::FromRef<S>,
{
    type Rejection = TimError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let gate: AdminGate = axum::extract::FromRef::from_ref(state);
        if !gate.enforced() {
            return Ok(AdminAuth);
        }
        let presented = parts
            .headers
            .get("x-tim-admin-token")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().as_bytes().to_vec())
            .or_else(|| {
                parts
                    .headers
                    .get(AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(|v| v.trim().as_bytes().to_vec())
            });
        let Some(p) = presented else {
            return Err(TimError::Unauthorized);
        };
        if !gate.verify(&p) {
            return Err(TimError::Unauthorized);
        }
        Ok(AdminAuth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_env(env: &str, require: bool) -> SecurityConfig {
        SecurityConfig {
            admin_token_env: env.into(),
            require_admin_token: require,
            ..SecurityConfig::default()
        }
    }

    #[test]
    fn errors_when_required_env_missing() {
        std::env::remove_var("TEST_ADMIN_TOKEN_MISSING");
        let cfg = cfg_with_env("TEST_ADMIN_TOKEN_MISSING", true);
        assert!(AdminGate::from_config(&cfg).is_err());
    }

    #[test]
    fn resolves_when_env_present() {
        std::env::set_var("TEST_ADMIN_TOKEN_SET", "sekret");
        let cfg = cfg_with_env("TEST_ADMIN_TOKEN_SET", true);
        let gate = AdminGate::from_config(&cfg).unwrap();
        assert!(gate.enforced());
        assert!(gate.verify(b"sekret"));
        assert!(!gate.verify(b"wrong"));
        assert!(!gate.verify(b"sekre")); // length mismatch
        std::env::remove_var("TEST_ADMIN_TOKEN_SET");
    }

    #[test]
    fn ungated_when_opted_out() {
        std::env::remove_var("TEST_ADMIN_TOKEN_UNSET");
        let cfg = cfg_with_env("TEST_ADMIN_TOKEN_UNSET", false);
        let gate = AdminGate::from_config(&cfg).unwrap();
        assert!(!gate.enforced());
        assert!(gate.verify(b"anything"));
    }

    #[test]
    fn ungated_when_env_name_empty_and_not_required() {
        let cfg = cfg_with_env("", false);
        let gate = AdminGate::from_config(&cfg).unwrap();
        assert!(!gate.enforced());
    }
}
