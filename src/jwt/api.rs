use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Accepts either `"aud"` or `["aud1","aud2"]` in JSON, mirroring
/// the Java TIM's `Object` field polymorphism.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multi(Vec<String>),
}

impl Audience {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Audience::Single(s) => vec![s],
            Audience::Multi(v) => v,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GenerateRequest {
    #[serde(rename = "JWTName", alias = "jwt_name")]
    pub jwt_name: String,
    pub content: BTreeMap<String, Value>,
    #[serde(rename = "expirationInMinutes", alias = "expiration_in_minutes")]
    pub expiration_in_minutes: i64,
    #[serde(default)]
    pub audience: Option<Audience>,
    #[serde(default, rename = "setCookie", alias = "set_cookie")]
    pub set_cookie: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub status: String,
    pub jwt_name: String,
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ValidateRequest {
    pub token: String,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub active: bool,
    pub reason: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<Vec<String>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub issued_at: Option<chrono::DateTime<chrono::Utc>>,
    pub jwt_id: Option<String>,
    pub claims: Option<BTreeMap<String, Value>>,
}

#[derive(Debug, Deserialize)]
pub struct ExtendRequest {
    pub token: String,
    #[serde(
        default,
        rename = "expirationInMinutes",
        alias = "expiration_in_minutes"
    )]
    pub expiration_in_minutes: Option<i64>,
    #[serde(default, rename = "setCookie", alias = "set_cookie")]
    pub set_cookie: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct BulkRevokeRequest {
    pub tokens: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BulkRevokeResponse {
    pub newly_revoked: usize,
    pub already_revoked: usize,
    pub failed: usize,
    pub results: Vec<BulkRevokeItem>,
}

#[derive(Debug, Serialize)]
pub struct BulkRevokeItem {
    pub token: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ListRequest {
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default, rename = "issuedAfter", alias = "issued_after")]
    pub issued_after: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, rename = "issuedBefore", alias = "issued_before")]
    pub issued_before: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, rename = "expiresAfter", alias = "expires_after")]
    pub expires_after: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, rename = "expiresBefore", alias = "expires_before")]
    pub expires_before: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub tokens: Vec<TokenSummary>,
    pub pagination: Pagination,
}

#[derive(Debug, Serialize)]
pub struct Pagination {
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct TokenSummary {
    pub jti: String,
    pub subject: Option<String>,
    pub jwt_name: Option<String>,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audience_deserializes_single_or_list() {
        let s: Audience = serde_json::from_str(r#""solo""#).unwrap();
        assert_eq!(s, Audience::Single("solo".into()));
        let m: Audience = serde_json::from_str(r#"["a","b"]"#).unwrap();
        assert_eq!(m, Audience::Multi(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn generate_request_accepts_camelcase_and_snake() {
        let camel = r#"{"JWTName":"n","content":{},"expirationInMinutes":10}"#;
        let snake = r#"{"jwt_name":"n","content":{},"expiration_in_minutes":10}"#;
        let a: GenerateRequest = serde_json::from_str(camel).unwrap();
        let b: GenerateRequest = serde_json::from_str(snake).unwrap();
        assert_eq!(a.jwt_name, "n");
        assert_eq!(b.expiration_in_minutes, 10);
    }
}
