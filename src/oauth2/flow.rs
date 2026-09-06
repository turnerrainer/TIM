use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use url::Url;

use crate::error::{Result, TimError};
use crate::oauth2::discovery::Discovery;
use crate::oauth2::idtoken;
use crate::oauth2::jwks::JwksCache;
use crate::oauth2::registry::{Provider, ProviderRegistry};
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
        .fetch_with(
            &provider.config.discovery_url,
            provider.config.allow_http_discovery,
        )
        .await?;
    enforce_jwks_pin(provider, &discovery)?;
    let state = random_hex(32);
    let nonce = random_hex(32);
    // RFC 7636 PKCE: generate a per-request verifier + S256 challenge.
    // Persist the verifier keyed by `state` so the callback can replay
    // it on the token endpoint. Providers that mandate PKCE (some
    // TARA/Google/Microsoft registrations) reject requests without a
    // challenge; providers that permit non-PKCE gain interception
    // resistance for the authorization code.
    let (pkce_verifier, pkce_challenge) = generate_pkce();

    sqlx::query(
        r#"
        INSERT INTO auth.oauth_state (state, provider_id, nonce, redirect_uri, pkce_verifier)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(&state)
    .bind(provider_id)
    .bind(&nonce)
    .bind(redirect_uri)
    .bind(&pkce_verifier)
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
        q.append_pair("code_challenge", &pkce_challenge);
        q.append_pair("code_challenge_method", "S256");
    }

    Ok(AuthUrl {
        authorization_url: u.into(),
        provider: provider_id.to_string(),
        state,
    })
}

/// RFC 7636 §4.1/§4.2: 32-byte random → base64url-no-pad verifier
/// (43 chars) and its SHA-256 base64url-no-pad challenge.
fn generate_pkce() -> (String, String) {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
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

    // Consume state (single-use). Postgres guarantees the DELETE ...
    // RETURNING is atomic under READ COMMITTED — two callbacks with
    // the same state cannot both receive a row. The age guard in the
    // WHERE clause also closes the sweeper race: an expired-but-not-
    // yet-swept row cannot be consumed. RFC 7636: return the persisted
    // PKCE verifier so it can be replayed on the token endpoint.
    let row: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        DELETE FROM auth.oauth_state
              WHERE state = $1
                AND provider_id = $2
                AND created_at > now() - make_interval(secs => $3::int)
          RETURNING nonce, provider_id, redirect_uri, pkce_verifier
        "#,
    )
    .bind(state)
    .bind(provider_id)
    .bind(state_max_age_seconds as i32)
    .fetch_optional(db)
    .await?;
    let (nonce, _provider_confirm, redirect_uri, pkce_verifier) = match row {
        Some(r) => r,
        None => {
            return Err(TimError::Unprocessable(
                "state not found, expired, or already consumed".into(),
            ));
        }
    };

    let discovery = registry
        .discovery
        .fetch_with(
            &provider.config.discovery_url,
            provider.config.allow_http_discovery,
        )
        .await?;
    enforce_jwks_pin(provider, &discovery)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| TimError::BadGateway(format!("build http client: {e}")))?;

    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
    ];
    if let Some(r) = redirect_uri.clone() {
        form.push(("redirect_uri", r));
    }
    // RFC 7636 §4.5: replay the stored verifier. Rows written before
    // this version's migration may lack the value; skip in that case
    // so long-lived state rows don't break in-flight logins.
    if let Some(v) = pkce_verifier.clone() {
        if !v.is_empty() {
            form.push(("code_verifier", v));
        }
    }
    let resp = http
        .post(&discovery.token_endpoint)
        // client_secret_basic, which OIDC Core makes the default when the client
        // registration does not say otherwise. Sending the pair as form fields
        // (client_secret_post) is what TARA rejects with 401 invalid_client.
        .basic_auth(&*provider.client_id, Some(&*provider.client_secret))
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
        // Carry the provider's error body. OAuth2 error responses name the actual problem
        // (invalid_client, invalid_grant, ...); dropping it leaves a bare 401 that cannot
        // be diagnosed without reproducing the request by hand. Bounded, and the body of a
        // failed token request holds no token material.
        let status = resp.status();
        let body: String = resp
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(512)
            .collect();
        return Err(TimError::BadGateway(format!(
            "token exchange returned {status}: {body}"
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

/// L3: refuse discovery whose `jwks_uri` differs from the operator's
/// pinned value. Signature verification would already fail closed for
/// keys the attacker doesn't own, but empty-JWKS is a trivial DoS
/// (no login can succeed) if the operator pinned the expected URI
/// and the pin doesn't match.
fn enforce_jwks_pin(provider: &Provider, discovery: &Discovery) -> Result<()> {
    let Some(pinned) = provider.config.jwks_uri.as_ref() else {
        return Ok(());
    };
    if pinned != &discovery.jwks_uri {
        return Err(TimError::Unprocessable(format!(
            "provider {}: discovery jwks_uri `{}` does not match pinned value `{pinned}`",
            provider.id, discovery.jwks_uri
        )));
    }
    Ok(())
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

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        let (verifier, challenge) = generate_pkce();
        // RFC 7636 §4.1: 43..=128 URL-safe chars.
        assert_eq!(verifier.len(), 43);
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')));
        // Challenge = base64url-nopad(SHA-256(verifier)).
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expected);
        assert_eq!(challenge.len(), 43); // SHA-256 → 32 bytes → 43 chars nopad
    }

    #[test]
    fn pkce_generates_unique_verifiers() {
        let (v1, _) = generate_pkce();
        let (v2, _) = generate_pkce();
        assert_ne!(v1, v2, "two calls must not collide");
    }

    fn provider_with_pin(pin: Option<&str>) -> Provider {
        use crate::config::{ProviderConfig, TokenValidationConfig};
        Provider {
            id: "p".into(),
            client_id: "cid".into(),
            client_secret: "cs".into(),
            config: ProviderConfig {
                name: "P".into(),
                discovery_url: "https://idp/.well-known".into(),
                client_id_env: String::new(),
                client_secret_env: String::new(),
                scopes: vec![],
                claim_mappings: Default::default(),
                token_validation: TokenValidationConfig::default(),
                allowed_redirect_uris: vec![],
                allow_http_discovery: false,
                jwks_uri: pin.map(str::to_string),
            },
        }
    }

    fn disc(jwks: &str) -> Discovery {
        Discovery {
            issuer: "https://idp".into(),
            authorization_endpoint: "https://idp/authorize".into(),
            token_endpoint: "https://idp/token".into(),
            userinfo_endpoint: None,
            jwks_uri: jwks.into(),
            grant_types_supported: vec![],
            response_types_supported: vec![],
        }
    }

    #[test]
    fn jwks_pin_none_is_a_no_op() {
        let p = provider_with_pin(None);
        assert!(enforce_jwks_pin(&p, &disc("https://anything/jwks")).is_ok());
    }

    #[test]
    fn jwks_pin_matches() {
        let p = provider_with_pin(Some("https://idp/jwks"));
        assert!(enforce_jwks_pin(&p, &disc("https://idp/jwks")).is_ok());
    }

    #[test]
    fn jwks_pin_rejects_mismatch() {
        let p = provider_with_pin(Some("https://idp/jwks"));
        let err = enforce_jwks_pin(&p, &disc("https://attacker/jwks")).unwrap_err();
        assert!(matches!(err, TimError::Unprocessable(_)));
    }
}
