use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::config::AppConfig;
use crate::crypto::JwtSigner;
use crate::error::{Result, TimError};
use crate::introspect::{IntrospectRequest, IntrospectionResponse, Introspector};
use crate::jwt::api::*;
use crate::jwt::service::{JwtService, StandardClaims};
use crate::oauth2::flow;
use crate::oauth2::session::MemoryStore;
use crate::oauth2::ProviderRegistry;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: PgPool,
    pub signer: Arc<JwtSigner>,
    pub jwt: Arc<JwtService>,
    pub providers: Arc<ProviderRegistry>,
    pub sessions: Arc<MemoryStore>,
}

pub fn build_router(state: AppState, cfg: &AppConfig) -> Router {
    let request_timeout = Duration::from_secs(cfg.server.request_timeout_seconds);

    Router::new()
        // Framework
        .route("/health", get(health))
        // Custom JWT
        .route("/jwt/custom/generate", post(jwt_generate))
        .route("/jwt/custom/validate", post(jwt_validate))
        .route("/jwt/custom/validate/boolean", post(jwt_validate_boolean))
        .route("/jwt/custom/revoke", post(jwt_revoke))
        .route("/jwt/custom/revoke/bulk", post(jwt_revoke_bulk))
        .route("/jwt/custom/extend", post(jwt_extend))
        .route("/jwt/custom/list/me", post(jwt_list_me))
        .route("/jwt/keys/public", get(jwks))
        // Introspection
        .route("/introspect", post(introspect_dispatch))
        .route("/introspect/types", get(introspect_types))
        // OAuth2
        .route("/auth/providers", get(auth_providers))
        .route("/auth/providers/:id", get(auth_provider_one))
        .route("/auth/login/:id", get(auth_login))
        .route("/auth/callback/:id", get(auth_callback))
        .route("/auth/session/validate", get(auth_session_validate))
        .route("/auth/profile", get(auth_profile))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/health", get(auth_health))
        .layer(DefaultBodyLimit::max(cfg.server.max_request_bytes))
        .layer(TimeoutLayer::new(request_timeout))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ---------------------- framework ----------------------

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status":"ok"})))
}

// ---------------------- custom JWT ----------------------

async fn jwt_generate(
    State(s): State<AppState>,
    Json(req): Json<GenerateRequest>,
) -> Result<Json<TokenResponse>> {
    let resp = s.jwt.generate(req).await?;
    Ok(Json(resp))
}

async fn jwt_validate(
    State(s): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateResponse>> {
    let resp = s.jwt.validate(req).await?;
    Ok(Json(resp))
}

async fn jwt_validate_boolean(
    State(s): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> Result<(StatusCode, String)> {
    let resp = s.jwt.validate(req).await?;
    let body = if resp.valid && resp.active {
        "true"
    } else {
        "false"
    };
    Ok((StatusCode::OK, body.to_string()))
}

async fn jwt_revoke(
    State(s): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> Result<Json<serde_json::Value>> {
    let newly = s.jwt.revoke(&req.token, req.reason).await?;
    Ok(Json(json!({
        "status": if newly { "revoked" } else { "already" },
        "already": !newly,
    })))
}

async fn jwt_revoke_bulk(
    State(s): State<AppState>,
    Json(req): Json<BulkRevokeRequest>,
) -> Result<(StatusCode, Json<BulkRevokeResponse>)> {
    let resp = s.jwt.bulk_revoke(req).await?;
    let status = if resp.failed > 0 || (resp.newly_revoked > 0 && resp.already_revoked > 0) {
        StatusCode::MULTI_STATUS
    } else {
        StatusCode::OK
    };
    Ok((status, Json(resp)))
}

async fn jwt_extend(
    State(s): State<AppState>,
    Json(req): Json<ExtendRequest>,
) -> Result<Json<TokenResponse>> {
    let resp = s.jwt.extend(req).await?;
    Ok(Json(resp))
}

async fn jwt_list_me(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<ListRequest>>,
) -> Result<Json<ListResponse>> {
    let token = bearer_token(&headers)?;
    let mut v = Validation::new(Algorithm::RS256);
    v.validate_exp = true;
    v.validate_aud = false;
    v.required_spec_claims.clear();
    let decoded = s.signer.verify::<StandardClaims>(&token, &v).map_err(|e| {
        tracing::debug!(error = %e, "list/me: bearer decode failed");
        TimError::Unauthorized
    })?;
    let sub = decoded.claims.sub.ok_or(TimError::Unauthorized)?;
    let req = body.map(|j| j.0).unwrap_or_default();
    let resp = s.jwt.list_for_subject(&sub, req).await?;
    Ok(Json(resp))
}

fn bearer_token(headers: &HeaderMap) -> Result<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(TimError::Unauthorized)?;
    raw.strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .ok_or(TimError::Unauthorized)
}

async fn jwks(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(s.signer.jwks())
}

// ---------------------- introspection ----------------------

#[derive(Debug, Deserialize)]
struct IntrospectForm {
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
}

async fn introspect_dispatch(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<IntrospectionResponse>> {
    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let req = if ct.starts_with("application/json") {
        let r: IntrospectRequest = serde_json::from_slice(&body)
            .map_err(|e| TimError::BadRequest(format!("json parse: {e}")))?;
        r
    } else if ct.starts_with("application/x-www-form-urlencoded") {
        let f: IntrospectForm = serde_urlencoded::from_bytes(&body)
            .map_err(|e| TimError::BadRequest(format!("form parse: {e}")))?;
        IntrospectRequest {
            token: f.token,
            token_type_hint: f.token_type_hint,
        }
    } else {
        return Err(TimError::UnsupportedMediaType);
    };
    let inspector = Introspector::new(s.jwt.clone());
    let resp = inspector.introspect(req).await?;
    Ok(Json(resp))
}

async fn introspect_types(State(s): State<AppState>) -> Json<serde_json::Value> {
    let inspector = Introspector::new(s.jwt.clone());
    Json(inspector.supported_types())
}

// ---------------------- OAuth2 ----------------------

async fn auth_providers(State(s): State<AppState>) -> Json<serde_json::Value> {
    let list = s.providers.list_public();
    Json(json!({
        "providers": list,
        "total": list.len().to_string(),
    }))
}

async fn auth_provider_one(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let p = s
        .providers
        .get(&id)
        .ok_or_else(|| TimError::NotFound(format!("provider {id}")))?;
    Ok(Json(json!({
        "id": p.id,
        "name": p.config.name,
        "scopes": p.config.scopes,
        "claim_mappings": p.config.claim_mappings,
    })))
}

#[derive(Debug, Deserialize)]
struct LoginQuery {
    #[serde(default)]
    redirect_uri: Option<String>,
}

async fn auth_login(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<LoginQuery>,
) -> Result<Json<flow::AuthUrl>> {
    let redirect_uri = q.redirect_uri.unwrap_or_else(|| {
        format!(
            "http://localhost:{}/auth/callback/{id}",
            s.config.server.port
        )
    });
    let url = flow::build_login_url(&s.db, &s.providers, &id, &redirect_uri).await?;
    Ok(Json(url))
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

async fn auth_callback(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Result<Json<flow::CallbackResult>> {
    let res =
        flow::complete_callback(&s.db, &s.providers, &s.sessions, &id, &q.code, &q.state).await?;
    Ok(Json(res))
}

#[derive(Debug, Deserialize)]
struct SessionQuery {
    session_id: String,
}

async fn auth_session_validate(
    State(s): State<AppState>,
    Query(q): Query<SessionQuery>,
) -> Result<Json<serde_json::Value>> {
    let session = s
        .sessions
        .get(&q.session_id)
        .ok_or_else(|| TimError::NotFound("session".into()))?;
    Ok(Json(json!({
        "valid": true,
        "session_id": session.id,
        "user_id": session.user_id,
        "provider": session.provider_id,
        "expires_at": session.expires_at,
        "last_activity": session.last_activity,
    })))
}

async fn auth_profile(
    State(s): State<AppState>,
    Query(q): Query<SessionQuery>,
) -> Result<Json<serde_json::Value>> {
    let session = s
        .sessions
        .get(&q.session_id)
        .ok_or_else(|| TimError::NotFound("session".into()))?;
    let mut body = json!({
        "user_id": session.user_id,
        "provider": session.provider_id,
    });
    if let Some(obj) = body.as_object_mut() {
        for (k, v) in session.profile {
            obj.insert(k, v);
        }
    }
    Ok(Json(body))
}

#[derive(Debug, Deserialize)]
struct LogoutQuery {
    session_id: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn auth_logout(
    State(s): State<AppState>,
    Query(q): Query<LogoutQuery>,
) -> Json<serde_json::Value> {
    let existed = s.sessions.revoke(&q.session_id);
    Json(json!({
        "status": if existed { "logged_out" } else { "not_found_ok" },
        "reason": q.reason,
    }))
}

async fn auth_health(State(s): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "service": "oauth2",
        "timestamp": chrono::Utc::now(),
        "available_providers": s.providers.ids().len(),
        "provider_ids": s.providers.ids(),
    }))
}
