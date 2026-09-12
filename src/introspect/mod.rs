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

impl IntrospectionResponse {
    /// RFC 7662 §2.2 — inactive responses SHOULD carry no additional
    /// data. Finding 21: enforce this at a single point instead of
    /// leaking claims on the expired/revoked paths.
    pub fn inactive() -> Self {
        Self {
            active: false,
            ..Default::default()
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
                return Ok(IntrospectionResponse::inactive());
            }
        };

        if claims.iss != self.jwt.cfg().issuer {
            return Ok(IntrospectionResponse::inactive());
        }

        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Ok(IntrospectionResponse::inactive());
        }
        let jti_uuid = match Uuid::parse_str(&claims.jti) {
            Ok(u) => u,
            Err(_) => return Ok(IntrospectionResponse::inactive()),
        };
        if self.jwt.denylist_lookup(jti_uuid).await? {
            return Ok(IntrospectionResponse::inactive());
        }

        Ok(IntrospectionResponse {
            active: true,
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

    pub fn supported_types(&self) -> serde_json::Value {
        serde_json::json!({
            "custom_jwt": "TIM-issued RS256 JWT tokens",
        })
    }
}
