use std::collections::HashMap;

use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use url::Url;

use crate::error::{Result, TimError};
use crate::oauth2::idtoken;
use crate::oauth2::jwks::JwksCache;
use crate::oauth2::registry::ProviderRegistry;
use crate::oauth2::session::{Session, SharedSessionStore};

/// Response returned by `GET /auth/login/{provider_id}`.
#[derive(Debug, Serialize)]
pub struct AuthUrl {
    pub authorization_url: String,
    pub provider: String,
    pub state: String,
}

/// Response returned by `GET /auth/callback/{provider_id}`.
#[derive(Debug, Serialize)]
pub struct CallbackResult {
    pub status: String,
    pub provider: String,
    pub session_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub user_profile: HashMap<String, serde_json::Value>,
}

/// Validate the client-supplied `redirect_uri` against the provider's
/// allow-list (finding 05). Falls back to a URL synthesised from
/// `server.public_base_url` (finding 30) when neither is provided.
pub fn resolve_redirect_uri(
    provider_id: &str,
    provider_allowed: &[String],
    public_base_url: &str,
    caller_supplied: Option<String>,
) -> Result<String> {
    if let Some(uri) = caller_supplied {
        if !provider_allowed.iter().any(|u| u == &uri) {
            return Err(TimError::BadRequest(format!(
                "redirect_uri `{uri}` is not on the provider's allow-list"
            )));
        }
        return Ok(uri);
    }
    // No caller redirect. Prefer the first allow-list entry (operators
    // set that as the canonical value); otherwise synthesise from
    // `public_base_url` if configured.
    if let Some(first) = provider_allowed.first() {
        return Ok(first.clone());
    }
    if public_base_url.is_empty() {
        return Err(TimError::BadRequest(
            "no redirect_uri supplied and neither provider.allowed_redirect_uris \
             nor server.public_base_url is configured"
                .into(),
        ));
    }
    let base = public_base_url.trim_end_matches('/');
    Ok(format!("{base}/auth/callback/{provider_id}"))
}

pub async fn build_login_url(
    db: &PgPool,
    registry: &ProviderRegistry,
    provider_id: &str,
    redirect_uri: &str,
) -> Result<AuthUrl> {
    let provider = registry
        .get(provider_id)
        .ok_or_else(|| TimError::NotFound(format!("unknown provider {provider_id}")))?;

    let discovery = registry
        .discovery
        .fetch(&provider.config.discovery_url)
        .await?;
    let state = random_hex(32);
    let nonce = random_hex(32);

    sqlx::query(
        r#"
        INSERT INTO auth.oauth_state (state, provider_id, nonce, redirect_uri)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(&state)
    .bind(provider_id)
    .bind(&nonce)
    .bind(redirect_uri)
    .execute(db)
    .await?;

    let mut u = Url::parse(&discovery.authorization_endpoint)
        .map_err(|e| TimError::BadGateway(format!("bad authorization_endpoint: {e}")))?;
    {
        let mut q = u.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", &provider.client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("scope", &provider.config.scopes.join(" "));
        q.append_pair("state", &state);
        q.append_pair("nonce", &nonce);
    }

    Ok(AuthUrl {
        authorization_url: u.into(),
        provider: provider_id.to_string(),
        state,
    })
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    #[allow(dead_code)]
    refresh_token: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn complete_callback(
    db: &PgPool,
    registry: &ProviderRegistry,
    jwks: &JwksCache,
    sessions: &SharedSessionStore,
    state_max_age_seconds: u64,
    provider_id: &str,
    code: &str,
    state: &str,
) -> Result<CallbackResult> {
    let provider = registry
        .get(provider_id)
        .ok_or_else(|| TimError::NotFound(format!("unknown provider {provider_id}")))?;

    // Consume state (single-use). Fix finding 11: reject rows older
    // than the configured max age via the WHERE clause.
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        DELETE FROM auth.oauth_state
              WHERE state = $1
                AND provider_id = $2
                AND created_at > now() - ($3::text || ' seconds')::interval
          RETURNING nonce, provider_id, redirect_uri
        "#,
    )
    .bind(state)
    .bind(provider_id)
    .bind(state_max_age_seconds.to_string())
    .fetch_optional(db)
    .await?;
    let (nonce, _provider_confirm, redirect_uri) = match row {
        Some(r) => r,
        None => {
            return Err(TimError::Unprocessable(
                "state not found, expired, or already consumed".into(),
            ));
        }
    };

    let discovery = registry
        .discovery
        .fetch(&provider.config.discovery_url)
        .await?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| TimError::BadGateway(format!("build http client: {e}")))?;

    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("client_id", provider.client_id.to_string()),
        ("client_secret", provider.client_secret.to_string()),
    ];
    if let Some(r) = redirect_uri.clone() {
        form.push(("redirect_uri", r));
    }
    let resp = http
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                TimError::UpstreamTimeout(format!("token endpoint: {e}"))
            } else {
                TimError::BadGateway(format!("token exchange: {e}"))
            }
        })?;
    if !resp.status().is_success() {
        return Err(TimError::BadGateway(format!(
            "token exchange returned {}",
            resp.status()
        )));
    }
    let tokens: TokenResponse = resp
        .json()
        .await
        .map_err(|e| TimError::BadGateway(format!("token response parse: {e}")))?;

    // FULL ID-token validation (finding 01/02). We require an ID
    // token because TIM's session model is built on `sub` from the
    // ID token — if the provider didn't return one, we can't build
    // an authenticated session.
    let id_token = tokens
        .id_token
        .as_deref()
        .ok_or_else(|| TimError::Unprocessable("token response has no id_token".into()))?;
    let verified = idtoken::verify(jwks, &discovery, provider, id_token, &nonce).await?;
    let (user_id, profile) = idtoken::profile_from_claims(provider, &verified.claims);

    // Session expiry: min(configured_ttl_cap, expires_in) (finding 09).
    let now = Utc::now();
    let ttl_cap = sessions.ttl_cap().as_secs() as i64;
    let candidate = tokens.expires_in.unwrap_or(ttl_cap);
    let effective = candidate.min(ttl_cap).max(1);
    let expires_at = now + Duration::seconds(effective);
    let session_id = random_hex(24);
    let session = Session {
        id: session_id.clone(),
        provider_id: provider_id.to_string(),
        user_id: user_id.clone(),
        created_at: now,
        last_activity: now,
        expires_at,
        profile: profile.clone(),
    };
    sessions.create(session).await?;
    // Prevent the unused-var warning on tokens.access_token; we keep
    // the deserialiser field for future refresh-token flows.
    let _ = tokens.access_token;

    Ok(CallbackResult {
        status: "ok".into(),
        provider: provider_id.into(),
        session_id,
        expires_at,
        user_profile: {
            let mut m = profile;
            m.insert("user_id".into(), serde_json::Value::String(user_id));
            m
        },
    })
}

pub(crate) fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex_encode(&buf)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_caller_when_allowed() {
        let allow = vec!["https://a".to_string(), "https://b".to_string()];
        let out =
            resolve_redirect_uri("p", &allow, "https://tim", Some("https://b".into())).unwrap();
        assert_eq!(out, "https://b");
    }

    #[test]
    fn resolve_rejects_caller_not_on_list() {
        let allow = vec!["https://a".to_string()];
        let err = resolve_redirect_uri("p", &allow, "https://tim", Some("https://evil".into()))
            .unwrap_err();
        assert!(matches!(err, TimError::BadRequest(_)));
    }

    #[test]
    fn resolve_falls_back_to_first_allow_entry() {
        let allow = vec!["https://canonical".to_string()];
        let out = resolve_redirect_uri("p", &allow, "https://tim", None).unwrap();
        assert_eq!(out, "https://canonical");
    }

    #[test]
    fn resolve_synthesises_from_public_base_url() {
        let out = resolve_redirect_uri("google", &[], "https://tim.example.com", None).unwrap();
        assert_eq!(out, "https://tim.example.com/auth/callback/google");
    }

    #[test]
    fn resolve_errors_when_no_source_available() {
        let err = resolve_redirect_uri("google", &[], "", None).unwrap_err();
        assert!(matches!(err, TimError::BadRequest(_)));
    }
}
