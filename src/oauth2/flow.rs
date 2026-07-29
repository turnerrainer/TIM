use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use url::Url;

use crate::error::{Result, TimError};
use crate::oauth2::registry::{Provider, ProviderRegistry};
use crate::oauth2::session::{MemoryStore, Session};

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
#[allow(dead_code)] // Preserved for logging/audit; used via serde only for MVP.
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
}

pub async fn complete_callback(
    db: &PgPool,
    registry: &ProviderRegistry,
    sessions: &MemoryStore,
    provider_id: &str,
    code: &str,
    state: &str,
) -> Result<CallbackResult> {
    let provider = registry
        .get(provider_id)
        .ok_or_else(|| TimError::NotFound(format!("unknown provider {provider_id}")))?;

    // Consume state (single-use).
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        DELETE FROM auth.oauth_state
              WHERE state = $1 AND provider_id = $2
          RETURNING nonce, provider_id, redirect_uri
        "#,
    )
    .bind(state)
    .bind(provider_id)
    .fetch_optional(db)
    .await?;
    let (nonce, _provider_confirm, redirect_uri) = match row {
        Some(r) => r,
        None => {
            return Err(TimError::Unprocessable(
                "state not found or already consumed".into(),
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

    // Extract subject + profile from ID token if present. Full JWKS
    // signature validation is task 005 (needs external-JWKS
    // validator infrastructure); the MVP relies on token exchange
    // being over TLS to a discovered token_endpoint plus nonce
    // verification below.
    let (user_id, profile) = extract_profile(provider, tokens.id_token.as_deref(), &nonce)?;

    let now = Utc::now();
    let expires_at =
        now + Duration::seconds(tokens.expires_in.unwrap_or(sessions.ttl().as_secs() as i64));
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
    sessions.create(session);

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

fn extract_profile(
    provider: &Provider,
    id_token: Option<&str>,
    expected_nonce: &str,
) -> Result<(String, HashMap<String, serde_json::Value>)> {
    let mut profile = HashMap::new();
    let Some(id_token) = id_token else {
        return Ok(("unknown".into(), profile));
    };
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(TimError::Unprocessable("id_token malformed".into()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| TimError::Unprocessable(format!("id_token payload decode: {e}")))?;
    let claims: HashMap<String, serde_json::Value> = serde_json::from_slice(&payload)
        .map_err(|e| TimError::Unprocessable(format!("id_token payload parse: {e}")))?;

    if let Some(n) = claims.get("nonce").and_then(|v| v.as_str()) {
        if n != expected_nonce {
            return Err(TimError::Unprocessable("id_token nonce mismatch".into()));
        }
    }
    // Map claims per provider.claim_mappings.
    for (canonical, provider_key) in &provider.config.claim_mappings {
        if let Some(v) = claims.get(provider_key) {
            profile.insert(canonical.clone(), v.clone());
        }
    }
    let user_id = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    Ok((user_id, profile))
}

fn random_hex(bytes: usize) -> String {
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
