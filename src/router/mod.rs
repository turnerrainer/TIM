use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, FromRef, Path, Query, Request, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{AppendHeaders, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
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
use crate::jwt::service::JwtService;
use crate::oauth2::flow;
use crate::oauth2::session::SharedSessionStore;
use crate::oauth2::ProviderRegistry;
use crate::security::admin::{AdminAuth, AdminGate};
use crate::security::headers;
use crate::security::introspect_auth::IntrospectionGate;
use crate::security::session_auth::SessionAuth;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: PgPool,
    pub signer: Arc<JwtSigner>,
    pub jwt: Arc<JwtService>,
    pub providers: Arc<ProviderRegistry>,
    pub sessions: SharedSessionStore,
    pub admin: AdminGate,
    pub introspect_gate: IntrospectionGate,
}

impl FromRef<AppState> for AdminGate {
    fn from_ref(input: &AppState) -> Self {
        input.admin.clone()
    }
}

pub fn build_router(state: AppState, cfg: &AppConfig) -> Router {
    let request_timeout = Duration::from_secs(cfg.server.request_timeout_seconds);
    let layers = headers::build(&cfg.security);

    let mut router = Router::new()
        .route("/health", get(health))
        // JVM 1.x used /healthz. Alias for operator compat.
        .route("/healthz", get(health))
        .route("/jwt/custom/generate", post(jwt_generate))
        .route("/jwt/custom/validate", post(jwt_validate))
        .route("/jwt/custom/validate/boolean", post(jwt_validate_boolean))
        .route("/jwt/custom/revoke", post(jwt_revoke))
        .route("/jwt/custom/revoke/bulk", post(jwt_revoke_bulk))
        .route("/jwt/custom/extend", post(jwt_extend))
        .route("/jwt/custom/list/me", post(jwt_list_me))
        .route("/jwt/keys/public", get(jwks))
        // Compat endpoints for the ~93 DSL files that still expect the
        // original Buerokratt TIM (JVM 1.x) cookie-borne shape.
        // Matrix rows E01/E03/E05/E06/E08/E09/E10/E11.
        .route("/jwt/verification-key", get(jwt_verification_key_compat))
        .route("/jwt/userinfo", get(jwt_userinfo_compat))
        .route("/jwt/custom-jwt-verify", post(jwt_custom_verify_compat))
        .route("/jwt/custom-jwt-userinfo", post(jwt_custom_userinfo_compat))
        .route("/jwt/custom-jwt-extend", post(jwt_custom_extend_compat))
        .route("/jwt/extend-jwt-session", get(jwt_extend_session_compat))
        .route(
            "/jwt/custom-jwt-blacklist",
            post(jwt_custom_blacklist_compat),
        )
        .route("/jwt/blacklist", post(jwt_blacklist_compat))
        .route("/introspect", post(introspect_dispatch))
        .route("/introspect/types", get(introspect_types))
        .route("/auth/providers", get(auth_providers))
        .route("/auth/providers/:id", get(auth_provider_one))
        .route("/auth/login/:id", get(auth_login))
        .route("/auth/callback/:id", get(auth_callback))
        .route("/auth/session/validate", get(auth_session_validate))
        .route("/auth/profile", get(auth_profile))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/health", get(auth_health))
        // Audit RUNTIME-v1 FN3 + fleet-strongholds §2.3/§6.1:
        // wrap the body-limit layer so 413 responses land as
        // well-formed JSON (`{"error":"payload_too_large","max":N}`)
        // instead of Axum's default bare-text
        // "Failed to buffer the request body: length limit exceeded".
        // Adds a Content-Length preflight so a client that DECLARES
        // an oversize body is rejected before any bytes are read.
        .layer(DefaultBodyLimit::max(cfg.server.max_request_bytes))
        .layer(axum::middleware::from_fn_with_state(
            cfg.server.max_request_bytes,
            body_size_error_mapper,
        ))
        .layer(TimeoutLayer::new(request_timeout))
        .layer(TraceLayer::new_for_http())
        // Audit LOG-v1 FN-LOG-2: emit one INFO line per completed request
        // for SOC2/ISO27001 access-log compliance. See src/access_log.rs.
        .layer(axum::middleware::from_fn(
            crate::access_log::access_log_middleware,
        ));

    // Response-header middleware — inserted here so every route
    // inherits them, including 404s produced by axum itself.
    if let Some(l) = layers.csp {
        router = router.layer(l);
    }
    if let Some(l) = layers.hsts {
        router = router.layer(l);
    }
    if let Some(l) = layers.referrer {
        router = router.layer(l);
    }
    if let Some(l) = layers.frame {
        router = router.layer(l);
    }
    if let Some(l) = layers.content_type {
        router = router.layer(l);
    }
    if let Some(l) = layers.cors {
        router = router.layer(l);
    }

    router.with_state(state)
}

// ---------------------- framework ----------------------

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"status": "ok"})))
}

/// Wrap the body-limit layer so 413 responses land as structured JSON
/// instead of Axum's default bare-text. See fleet-strongholds §2.3.
///
/// Two paths:
/// 1. **Content-Length preflight** — a client that declares an
///    oversize body via `Content-Length` gets 413 immediately, before
///    any bytes are read into memory. Guards against the pattern
///    where Axum's rejection reads the whole body first.
/// 2. **Response rewrite** — an actual body-limit rejection produced
///    by an axum extractor (`Bytes` / `Json` / `Form`) returns 413
///    with a bare-text body. This wrapper preserves the status code
///    but rewrites the body to `{"error":"payload_too_large","max":N}`
///    matching `TimError::PayloadTooLarge`.
async fn body_size_error_mapper(State(max): State<usize>, req: Request, next: Next) -> Response {
    // Preflight: fast-reject when the client declares an oversize body.
    // A missing / malformed Content-Length means "unknown length" — we
    // fall through to the streaming cap enforced by DefaultBodyLimit.
    if let Some(cl) = req.headers().get(CONTENT_LENGTH) {
        if let Ok(s) = cl.to_str() {
            if let Ok(n) = s.parse::<usize>() {
                if n > max {
                    return payload_too_large(max);
                }
            }
        }
    }
    let response = next.run(req).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
        // Preserve the extractor's status but rewrite the body.
        return payload_too_large(max);
    }
    response
}

fn payload_too_large(max: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({ "error": "payload_too_large", "max": max })),
    )
        .into_response()
}

// ---------------------- custom JWT ----------------------

async fn jwt_generate(
    _admin: AdminAuth,
    State(s): State<AppState>,
    Json(req): Json<GenerateRequest>,
) -> Result<Response> {
    let set_cookie_wanted = req.set_cookie.unwrap_or(false);
    let jwt_name = req.jwt_name.clone();
    let resp = s.jwt.generate(req).await?;
    let cookie_value = set_cookie_wanted.then(|| build_cookie(&jwt_name, &resp.token));
    Ok(with_optional_set_cookie(Json(resp), cookie_value))
}

async fn jwt_validate(
    State(s): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> Result<Response> {
    let resp = s.jwt.validate(req).await?;
    // Finding 16 & JVM parity: return 401 when the token is invalid
    // rather than always 200. Callers switching on HTTP status
    // (Java client) now see the same wire behavior.
    let status = if resp.valid && resp.active {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    };
    Ok((status, Json(resp)).into_response())
}

async fn jwt_validate_boolean(
    State(s): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> Result<Response> {
    let resp = s.jwt.validate(req).await?;
    let ok = resp.valid && resp.active;
    let body = if ok { "true" } else { "false" };
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    };
    Ok((
        status,
        [(CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
        body,
    )
        .into_response())
}

async fn jwt_revoke(
    _admin: AdminAuth,
    State(s): State<AppState>,
    Json(req): Json<ValidateRequest>,
) -> Result<Response> {
    let newly = s.jwt.revoke(&req.token, req.reason).await?;
    // Finding 16: JVM returns 409 for already-revoked idempotent
    // repeats.
    let (status, body) = if newly {
        (
            StatusCode::OK,
            json!({
                "status": "revoked",
                "message": "Token has been successfully revoked",
            }),
        )
    } else {
        (
            StatusCode::CONFLICT,
            json!({
                "status": "already_revoked",
                "message": "Token was already revoked",
            }),
        )
    };
    Ok((status, Json(body)).into_response())
}

async fn jwt_revoke_bulk(
    _admin: AdminAuth,
    State(s): State<AppState>,
    Json(req): Json<BulkRevokeRequest>,
) -> Result<Response> {
    let resp = s.jwt.bulk_revoke(req).await?;
    // Finding 16: MULTI_STATUS on partial success; 409 on
    // all-already-revoked; 400 when all failed.
    let status = if resp.failed > 0 && resp.newly_revoked == 0 && resp.already_revoked == 0 {
        StatusCode::BAD_REQUEST
    } else if resp.failed > 0 || (resp.newly_revoked > 0 && resp.already_revoked > 0) {
        StatusCode::MULTI_STATUS
    } else if resp.newly_revoked == 0 && resp.already_revoked > 0 {
        StatusCode::CONFLICT
    } else {
        StatusCode::OK
    };
    Ok((status, Json(resp)).into_response())
}

async fn jwt_extend(
    _admin: AdminAuth,
    State(s): State<AppState>,
    Json(req): Json<ExtendRequest>,
) -> Result<Response> {
    let set_cookie_wanted = req.set_cookie.unwrap_or(false);
    let resp = s.jwt.extend(req).await?;
    let cookie_value = set_cookie_wanted.then(|| build_cookie("EXTENDED_TOKEN", &resp.token));
    Ok(with_optional_set_cookie(Json(resp), cookie_value))
}

async fn jwt_list_me(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<ListRequest>>,
) -> Result<Json<ListResponse>> {
    let token = bearer_token(&headers)?;
    // Finding 13: authenticate_bearer does the denylist check.
    let sub = s.jwt.authenticate_bearer(&token).await?;
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
        .map(|s| s.trim().to_string())
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
    // RFC 7662 §2.1: optional client authentication. Default off for
    // backwards compatibility with existing downstream callers.
    // Operators SHOULD enable it in production so unauthenticated
    // enumeration + DB-load DoS against the denylist SELECT is closed.
    if s.introspect_gate.required() {
        let raw = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(TimError::Unauthorized)?;
        s.introspect_gate.verify_basic(raw)?;
    }
    let ct = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let req = if ct.starts_with("application/json") {
        serde_json::from_slice::<IntrospectRequest>(&body)
            .map_err(|e| TimError::BadRequest(format!("json parse: {e}")))?
    } else if ct.starts_with("application/x-www-form-urlencoded") {
        let f: IntrospectForm = serde_urlencoded::from_bytes(&body)
            .map_err(|e| TimError::BadRequest(format!("form parse: {e}")))?;
        IntrospectRequest {
            token: f.token,
            token_type_hint: f.token_type_hint,
        }
    } else {
        // Finding 22: be permissive. Try JSON first, then form —
        // RFC 7662 §2.1 does not require 415 on missing content-type.
        if let Ok(r) = serde_json::from_slice::<IntrospectRequest>(&body) {
            r
        } else if let Ok(f) = serde_urlencoded::from_bytes::<IntrospectForm>(&body) {
            IntrospectRequest {
                token: f.token,
                token_type_hint: f.token_type_hint,
            }
        } else {
            return Err(TimError::BadRequest(
                "body must be JSON or application/x-www-form-urlencoded".into(),
            ));
        }
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
    let provider = s
        .providers
        .get(&id)
        .ok_or_else(|| TimError::NotFound(format!("unknown provider {id}")))?;
    let redirect_uri = flow::resolve_redirect_uri(
        &id,
        &provider.config.allowed_redirect_uris,
        &s.config.server.public_base_url,
        q.redirect_uri,
    )?;
    let url = flow::build_login_url(&s.db, &s.providers, &id, &redirect_uri).await?;
    Ok(Json(url))
}

/// Finding 04: accept `error` + `error_description` alongside
/// `code`/`state` so IdP failures don't 400 as "missing field".
#[derive(Debug, Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

async fn auth_callback(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Result<Response> {
    if let Some(err) = q.error {
        let body = json!({
            "status": "error",
            "provider": id,
            "error": err,
            "error_description": q.error_description,
        });
        return Ok((StatusCode::BAD_REQUEST, Json(body)).into_response());
    }
    let code = q
        .code
        .ok_or_else(|| TimError::BadRequest("callback missing `code`".into()))?;
    let state = q
        .state
        .ok_or_else(|| TimError::BadRequest("callback missing `state`".into()))?;
    let res = flow::complete_callback(
        &s.db,
        &s.providers,
        &s.providers.jwks,
        &s.sessions,
        s.config.oauth2.state_max_age_seconds,
        &id,
        &code,
        &state,
    )
    .await?;
    Ok(Json(res).into_response())
}

async fn auth_session_validate(
    State(s): State<AppState>,
    session: SessionAuth,
) -> Result<Json<serde_json::Value>> {
    let sess = s
        .sessions
        .get(&session.session_id)
        .await?
        .ok_or_else(|| TimError::NotFound("session".into()))?;
    // Finding 29: touch on successful validate.
    let _ = s.sessions.touch(&session.session_id).await;
    Ok(Json(json!({
        "valid": true,
        "session_id": sess.id,
        "user_id": sess.user_id,
        "provider": sess.provider_id,
        "expires_at": sess.expires_at,
        "last_activity": sess.last_activity,
    })))
}

async fn auth_profile(
    State(s): State<AppState>,
    session: SessionAuth,
) -> Result<Json<serde_json::Value>> {
    let sess = s
        .sessions
        .get(&session.session_id)
        .await?
        .ok_or_else(|| TimError::NotFound("session".into()))?;
    let _ = s.sessions.touch(&session.session_id).await;
    let mut body = json!({
        "user_id": sess.user_id,
        "provider": sess.provider_id,
    });
    if let Some(obj) = body.as_object_mut() {
        for (k, v) in sess.profile {
            obj.insert(k, v);
        }
    }
    Ok(Json(body))
}

#[derive(Debug, Deserialize)]
struct LogoutBody {
    #[serde(default)]
    reason: Option<String>,
}

async fn auth_logout(
    State(s): State<AppState>,
    session: SessionAuth,
    body: Option<Json<LogoutBody>>,
) -> Result<Json<serde_json::Value>> {
    let existed = s.sessions.revoke(&session.session_id).await?;
    let reason = body.and_then(|b| b.0.reason);
    Ok(Json(json!({
        "status": if existed { "logged_out" } else { "not_found_ok" },
        "reason": reason,
    })))
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

// ---------------------- helpers ----------------------

fn build_cookie(name: &str, token: &str) -> HeaderValue {
    // Finding 15 restores JVM's Set-Cookie shape. Adds `Secure` +
    // `SameSite=Lax` — JVM omitted both, which is unsafe.
    HeaderValue::from_str(&format!(
        "{name}={token}; Path=/; HttpOnly; Secure; SameSite=Lax"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn with_optional_set_cookie<B: IntoResponse>(body: B, cookie: Option<HeaderValue>) -> Response {
    match cookie {
        Some(c) => (AppendHeaders([(SET_COOKIE, c)]), body).into_response(),
        None => body.into_response(),
    }
}

/// Extract a single cookie value by name from the `Cookie` request
/// header. Returns `None` if the header is missing, the name is not
/// among the cookies, or the value is empty. Handles the RFC 6265
/// `name=value; name2=value2` form; does not URL-decode the value —
/// TIM's cookies contain raw JWTs which have no `%`-encoded chars.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name && !v.is_empty() {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

// ---------------------- compat: original Buerokratt TIM ----------------------
//
// Finding 31: three legacy endpoints kept alive for the 93 DSL files
// that reference `check-user-authority.yml` and `logout.yml`. All
// three read the JWT from the cookie whose name is configured via
// `jwt.cookie_name` (default `"jwt"`).
//
// - GET  /jwt/userinfo             — PUBLIC. Decodes the cookie JWT and
//                                    returns subject + claims.
// - POST /jwt/custom-jwt-blacklist — admin-gated. Body is the cookie
//                                    name (matches JVM shape).
// - POST /jwt/blacklist            — admin-gated. Three modes:
//                                    ?jwt=<uuid>, ?sessionId=<id>,
//                                    or cookie fallback.

async fn jwt_userinfo_compat(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let cookie_name = &s.config.jwt.cookie_name;
    let token = cookie_value(&headers, cookie_name)
        .ok_or_else(|| TimError::BadRequest(format!("cookie `{cookie_name}` not present")))?;
    // Reuse the same auth path as /jwt/custom/list/me:
    // signature + exp + denylist all checked.
    let sub = s.jwt.authenticate_bearer(&token).await?;
    // Decode again to hand back the full claim set — validate() gives
    // us the JVM-shape validation response with `claims` populated.
    let resp = s
        .jwt
        .validate(crate::jwt::api::ValidateRequest {
            token: token.clone(),
            audience: None,
            issuer: None,
            reason: None,
        })
        .await?;
    Ok(Json(json!({
        "userinfo": {
            "subject": sub,
            "issuer": resp.issuer,
            "audience": resp.audience,
            "expires_at": resp.expires_at,
            "issued_at": resp.issued_at,
            "jwt_id": resp.jwt_id,
            "claims": resp.claims,
        },
    })))
}

async fn jwt_custom_blacklist_compat(
    _admin: AdminAuth,
    State(s): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response> {
    // Original JVM CustomJwtController.blacklistCustomJwtToken takes
    // `@RequestBody String cookieName` — so body is the cookie name
    // to look up, and the value is the JWT to revoke. Trim quotes /
    // whitespace defensively.
    let cookie_name = body.trim().trim_matches('"').to_string();
    if cookie_name.is_empty() {
        return Err(TimError::BadRequest(
            "request body must be the cookie name to blacklist".into(),
        ));
    }
    let Some(token) = cookie_value(&headers, &cookie_name) else {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({
                "status": "not_found",
                "message": format!("cookie `{cookie_name}` not present on request"),
            })),
        )
            .into_response());
    };
    match s
        .jwt
        .revoke(&token, Some("custom-jwt-blacklist".into()))
        .await
    {
        Ok(true) => Ok((StatusCode::OK, Json(json!({"status": "blacklisted"}))).into_response()),
        Ok(false) => Ok((
            StatusCode::CONFLICT,
            Json(json!({"status": "already_blacklisted"})),
        )
            .into_response()),
        Err(TimError::BadRequest(msg)) => Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "failed", "message": msg})),
        )
            .into_response()),
        Err(other) => Err(other),
    }
}

#[derive(Debug, Deserialize)]
struct LegacyBlacklistQuery {
    #[serde(default)]
    jwt: Option<String>,
    #[serde(default, alias = "session_id")]
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

async fn jwt_blacklist_compat(
    _admin: AdminAuth,
    State(s): State<AppState>,
    Query(q): Query<LegacyBlacklistQuery>,
    headers: HeaderMap,
) -> Result<Response> {
    // Priority order matches the JVM:
    //   1. cookie present → treat as custom JWT revoke
    //   2. ?jwt=<uuid>    → jti-only revoke via metadata lookup
    //   3. ?sessionId=<>  → OAuth2 session revoke
    let cookie_name = &s.config.jwt.cookie_name;
    if let Some(token) = cookie_value(&headers, cookie_name) {
        return match s.jwt.revoke(&token, q.reason.clone()).await {
            Ok(true) => Ok(status_body(StatusCode::OK, "blacklisted", None)),
            Ok(false) => Ok(status_body(
                StatusCode::CONFLICT,
                "already_blacklisted",
                None,
            )),
            Err(TimError::BadRequest(msg)) => {
                Ok(status_body(StatusCode::BAD_REQUEST, "failed", Some(msg)))
            }
            Err(other) => Err(other),
        };
    }
    if let Some(jwt_id) = q.jwt {
        let jti = uuid::Uuid::parse_str(&jwt_id)
            .map_err(|_| TimError::BadRequest(format!("?jwt=`{jwt_id}` is not a valid UUID")))?;
        return match s.jwt.revoke_by_jti(jti, q.reason).await? {
            Some(true) => Ok(status_body(StatusCode::OK, "blacklisted", None)),
            Some(false) => Ok(status_body(
                StatusCode::CONFLICT,
                "already_blacklisted",
                None,
            )),
            None => Ok(status_body(
                StatusCode::NOT_FOUND,
                "not_found",
                Some(format!("no TIM-issued JWT with jti {jwt_id}")),
            )),
        };
    }
    if let Some(sid) = q.session_id {
        let existed = s.sessions.revoke(&sid).await?;
        return Ok(status_body(
            if existed {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            },
            if existed { "logged_out" } else { "not_found" },
            None,
        ));
    }
    Err(TimError::BadRequest(
        "supply one of: cookie, ?jwt=<uuid>, ?sessionId=<id>".into(),
    ))
}

fn status_body(code: StatusCode, status: &'static str, message: Option<String>) -> Response {
    let mut body = json!({ "status": status });
    if let (Some(msg), Some(obj)) = (message, body.as_object_mut()) {
        obj.insert("message".into(), serde_json::Value::String(msg));
    }
    (code, Json(body)).into_response()
}

// ---------------------- more legacy compat (JVM 1.x) ----------------------
//
// Coverage matrix rows E01, E05, E08, E10, E11.

/// `GET /jwt/verification-key` — matrix row E01.
///
/// JVM 1.x exposed the JWT signing public key as a PEM string; some
/// Java DSL consumers still expect that shape. The modern equivalent
/// is `GET /jwt/keys/public` (JWKS). Public — no auth required.
async fn jwt_verification_key_compat(State(s): State<AppState>) -> Result<Response> {
    let pem = s.signer.public_pem()?;
    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
        pem,
    )
        .into_response())
}

/// `POST /jwt/custom-jwt-verify` — matrix row E08.
///
/// JVM 1.x body is the cookie name; server reads that cookie and
/// verifies the JWT it carries. Returns 200 on active, 401 on
/// inactive. Public — no admin token (same as modern
/// `/jwt/custom/validate`).
async fn jwt_custom_verify_compat(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response> {
    let cookie_name = body.trim().trim_matches('"').to_string();
    if cookie_name.is_empty() {
        return Err(TimError::BadRequest(
            "request body must be the cookie name to verify".into(),
        ));
    }
    let Some(token) = cookie_value(&headers, &cookie_name) else {
        return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({"valid": false, "reason": "cookie_not_present"})),
        )
            .into_response());
    };
    let resp = s
        .jwt
        .validate(crate::jwt::api::ValidateRequest {
            token,
            audience: None,
            issuer: None,
            reason: None,
        })
        .await?;
    let code = if resp.valid && resp.active {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    };
    Ok((code, Json(resp)).into_response())
}

/// `POST /jwt/custom-jwt-userinfo` — matrix row E11.
///
/// JVM 1.x: body is the cookie name; response is the token's claim
/// map. Differs from `/jwt/userinfo` (matrix row E03) in that the
/// caller specifies which cookie to read rather than relying on
/// `jwt.cookie_name`. Public — no admin token.
async fn jwt_custom_userinfo_compat(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response> {
    let cookie_name = body.trim().trim_matches('"').to_string();
    if cookie_name.is_empty() {
        return Err(TimError::BadRequest(
            "request body must be the cookie name to read".into(),
        ));
    }
    let Some(token) = cookie_value(&headers, &cookie_name) else {
        return Err(TimError::BadRequest(format!(
            "cookie `{cookie_name}` not present on request"
        )));
    };
    let sub = s.jwt.authenticate_bearer(&token).await?;
    let resp = s
        .jwt
        .validate(crate::jwt::api::ValidateRequest {
            token,
            audience: None,
            issuer: None,
            reason: None,
        })
        .await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "userinfo": {
                "subject": sub,
                "issuer": resp.issuer,
                "audience": resp.audience,
                "expires_at": resp.expires_at,
                "issued_at": resp.issued_at,
                "jwt_id": resp.jwt_id,
                "claims": resp.claims,
            },
            "cookie_name": cookie_name,
        })),
    )
        .into_response())
}

/// `POST /jwt/custom-jwt-extend` — matrix row E10.
///
/// JVM 1.x: body is the cookie name; server reads that cookie, calls
/// extend, sets Set-Cookie with the new token on the response. Admin-
/// gated (same as modern `/jwt/custom/extend`).
async fn jwt_custom_extend_compat(
    _admin: AdminAuth,
    State(s): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response> {
    let cookie_name = body.trim().trim_matches('"').to_string();
    if cookie_name.is_empty() {
        return Err(TimError::BadRequest(
            "request body must be the cookie name to extend".into(),
        ));
    }
    let Some(token) = cookie_value(&headers, &cookie_name) else {
        return Err(TimError::BadRequest(format!(
            "cookie `{cookie_name}` not present on request"
        )));
    };
    let resp = s
        .jwt
        .extend(crate::jwt::api::ExtendRequest {
            token,
            expiration_in_minutes: None,
            set_cookie: Some(true),
        })
        .await?;
    // Set the NEW token under the SAME cookie name the caller used.
    let cookie = build_cookie(&cookie_name, &resp.token);
    Ok(with_optional_set_cookie(Json(resp), Some(cookie)))
}

/// `GET /jwt/extend-jwt-session` — matrix row E05.
///
/// JVM 1.x: reads JWT from `jwt.cookie_name` cookie, extends,
/// sets the refreshed cookie. GET method (rare for state-changing
/// operations, but that's what JVM 1.x did). Admin-gated.
async fn jwt_extend_session_compat(
    _admin: AdminAuth,
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<Response> {
    let cookie_name = &s.config.jwt.cookie_name;
    let Some(token) = cookie_value(&headers, cookie_name) else {
        return Err(TimError::BadRequest(format!(
            "cookie `{cookie_name}` not present on request"
        )));
    };
    let resp = s
        .jwt
        .extend(crate::jwt::api::ExtendRequest {
            token,
            expiration_in_minutes: None,
            set_cookie: Some(true),
        })
        .await?;
    let cookie = build_cookie(cookie_name, &resp.token);
    Ok(with_optional_set_cookie(Json(resp), Some(cookie)))
}
