//! RFC 7662 token introspection dispatcher.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::Result;
use crate::jwt::service::{JwtService, StandardClaims};

#[derive(Debug, Serialize, Default)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_claims: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

pub struct Introspector {
    jwt: Arc<JwtService>,
}

impl Introspector {
    pub fn new(jwt: Arc<JwtService>) -> Self {
        Self { jwt }
    }

    pub async fn introspect(&self, req: IntrospectRequest) -> Result<IntrospectionResponse> {
        // Parse without validation to inspect claims.
        let v = JwtService::permissive_validation();
        let claims = match self.jwt.signer().verify::<StandardClaims>(&req.token, &v) {
            Ok(d) => d.claims,
            Err(e) => {
                tracing::debug!(error = %e, "introspect: token decode failed");
                // Malformed or wrong signature — RFC 7662 §2.2 says
                // return active: false without leaking why.
                return Ok(IntrospectionResponse {
                    active: false,
                    ..Default::default()
                });
            }
        };

        let issuer_matches = claims.iss == self.jwt.cfg().issuer;
        if !issuer_matches {
            // Unknown issuer — hook point for task 005 (external
            // JWKS validators). MVP returns inactive per RFC 7662.
            return Ok(IntrospectionResponse {
                active: false,
                ..Default::default()
            });
        }

        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Ok(IntrospectionResponse {
                active: false,
                iss: Some(claims.iss),
                sub: claims.sub,
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                jti: Some(claims.jti),
                aud: claims.aud,
                token_type: Some("custom_jwt".into()),
                extra_claims: claims.extra,
                ..Default::default()
            });
        }
        // Denylist check.
        let jti_uuid = match Uuid::parse_str(&claims.jti) {
            Ok(u) => u,
            Err(_) => {
                return Ok(IntrospectionResponse {
                    active: false,
                    ..Default::default()
                });
            }
        };
        let denylisted = self.is_denylisted(jti_uuid).await?;
        let active = !denylisted;

        Ok(IntrospectionResponse {
            active,
            iss: Some(claims.iss),
            sub: claims.sub,
            aud: claims.aud,
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            jti: Some(claims.jti),
            token_type: Some("custom_jwt".into()),
            extra_claims: claims.extra,
            ..Default::default()
        })
    }

    async fn is_denylisted(&self, jti: Uuid) -> Result<bool> {
        // Reach into the JWT service's pool via a fresh query — we
        // don't expose the pool publicly. Reuse via a small helper.
        // (Keeping the pool private preserves encapsulation.)
        self.jwt.denylist_lookup(jti).await
    }

    pub fn supported_types(&self) -> serde_json::Value {
        serde_json::json!({
            "custom_jwt": "TIM-issued RS256 JWT tokens",
        })
    }
}
