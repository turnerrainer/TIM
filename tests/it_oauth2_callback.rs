//! End-to-end coverage for the OAuth2 callback path — the test that
//! *should have existed* when finding 01 (ID token never verified)
//! was still a bug. Uses `mockito` to stand up a mock IdP with a
//! JWKS endpoint, a token endpoint, and a discovery document.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use tim::{
    config::{AppConfig, JwtConfig, ProviderConfig, TokenValidationConfig},
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::{session::MemoryStore, ProviderRegistry},
    router::{build_router, AppState},
    security::admin::AdminGate,
};
use tower::ServiceExt;

mod common;

const TEST_KEY: &str = include_str!("fixtures/test-jwt-private.pem");

async fn setup_with_provider(server_url: &str) -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;
    let pool = db::connect(
        &db_url,
        &tim::config::DatabaseConfig {
            ..tim::config::DatabaseConfig::default()
        },
    )
    .await
    .ok()?;
    db::run_migrations(&pool).await.ok()?;
    sqlx::query("TRUNCATE TABLE auth.oauth_state, auth.session")
        .execute(&pool)
        .await
        .ok()?;

    // Provider needs env-set client id + secret.
    std::env::set_var("MOCK_IDP_CLIENT_ID", "tim-client");
    std::env::set_var("MOCK_IDP_CLIENT_SECRET", "shhh");

    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    cfg.server.public_base_url = "https://tim.example.com".into();
    let mut provider = ProviderConfig {
        name: "MockIdP".into(),
        discovery_url: format!("{server_url}/.well-known/openid-configuration"),
        client_id_env: "MOCK_IDP_CLIENT_ID".into(),
        client_secret_env: "MOCK_IDP_CLIENT_SECRET".into(),
        scopes: vec!["openid".into()],
        claim_mappings: Default::default(),
        token_validation: TokenValidationConfig::default(),
        allowed_redirect_uris: vec!["https://tim.example.com/auth/callback/mock".into()],
        allow_http_discovery: true,
    };
    provider
        .claim_mappings
        .insert("email".into(), "email".into());
    cfg.oauth2.providers.insert("mock".into(), provider);

    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, "callback-it".into()).ok()?;
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(ProviderRegistry::from_config(&cfg.oauth2).await.ok()?);
    let sessions = Arc::new(MemoryStore::new(Duration::from_secs(3600)));
    let admin = AdminGate::from_config(&cfg.security).ok()?;
    let state = AppState {
        config: Arc::new(cfg.clone()),
        db: pool,
        signer: Arc::new(signer),
        jwt,
        providers,
        sessions,
        admin,
    };
    Some(build_router(state, &cfg))
}

async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, Value) {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(path)
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn generate_idp_keypair() -> (RsaPrivateKey, RsaPublicKey, String) {
    // 2048-bit keys are slow-ish; tests generate once per case. In a
    // busier suite we'd share via `once_cell`.
    let mut rng = rand::thread_rng();
    let sk = RsaPrivateKey::new(&mut rng, 2048).expect("gen key");
    let pk = RsaPublicKey::from(&sk);
    let pkcs8 = sk
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string();
    (sk, pk, pkcs8)
}

fn jwk_from_public(pk: &RsaPublicKey, kid: &str) -> Value {
    let n = URL_SAFE_NO_PAD.encode(pk.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pk.e().to_bytes_be());
    json!({
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": n,
        "e": e,
    })
}

fn sign_id_token(pem: &str, claims: &Value, kid: &str) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    encode(&header, claims, &key).expect("encode id_token")
}

#[tokio::test]
async fn callback_verifies_signature_and_nonce_before_session_create() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();

    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "idp-kid-1";

    // Discovery document
    let discovery_body = json!({
        "issuer": base.clone(),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
    })
    .to_string();
    let _m_disc = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&discovery_body)
        .expect_at_least(1)
        .create_async()
        .await;
    // JWKS
    let jwks_body = json!({ "keys": [ jwk_from_public(&pk, kid) ] }).to_string();
    let _m_jwks = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&jwks_body)
        .expect_at_least(1)
        .create_async()
        .await;

    let Some(router) = setup_with_provider(&base).await else {
        return;
    };

    // Step 1: kick off login, get state + nonce persisted in oauth_state.
    let (s, body) = get_json(&router, "/auth/login/mock").await;
    assert_eq!(s, StatusCode::OK, "login: {body:?}");
    let state = body["state"].as_str().expect("state").to_string();

    // Read the nonce that TIM stored — we need it to build a valid
    // id_token. In production the IdP has already seen this via the
    // authorization URL; in the test we go directly to the DB.
    let db_url = std::env::var("TIM_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
    let (nonce,): (String,) = sqlx::query_as("SELECT nonce FROM auth.oauth_state WHERE state = $1")
        .bind(&state)
        .fetch_one(&pool)
        .await
        .unwrap();

    // Build a well-formed ID token signed by the mock IdP.
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": base.clone(),
        "sub": "user-xyz",
        "aud": "tim-client",
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "email": "user@example.com",
    });
    let id_token = sign_id_token(&pem, &claims, kid);

    // Token endpoint returns access_token + id_token.
    let token_body = json!({
        "access_token": "opaque-access",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    })
    .to_string();
    let _m_tok = server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&token_body)
        .expect(1)
        .create_async()
        .await;

    // Step 2: hit the callback with valid code+state.
    let (s, body) = get_json(
        &router,
        &format!("/auth/callback/mock?code=any-code&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "callback body: {body:?}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["user_profile"]["user_id"], "user-xyz");
    assert_eq!(body["user_profile"]["email"], "user@example.com");
}

#[tokio::test]
async fn callback_rejects_tampered_id_token_signature() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let (_bad_sk, _bad_pk, bad_pem) = generate_idp_keypair(); // different key
    let kid = "idp-kid-1";

    let discovery_body = json!({
        "issuer": base.clone(),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
    })
    .to_string();
    let _m_disc = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_body(&discovery_body)
        .expect_at_least(1)
        .create_async()
        .await;
    let jwks_body = json!({ "keys": [ jwk_from_public(&pk, kid) ] }).to_string();
    let _m_jwks = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_body(&jwks_body)
        .expect_at_least(1)
        .create_async()
        .await;
    let _ = pem; // unused — we're going to sign with the WRONG key.

    let Some(router) = setup_with_provider(&base).await else {
        return;
    };
    let (_s, body) = get_json(&router, "/auth/login/mock").await;
    let state = body["state"].as_str().unwrap().to_string();
    let db_url = std::env::var("TIM_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
    let (nonce,): (String,) = sqlx::query_as("SELECT nonce FROM auth.oauth_state WHERE state = $1")
        .bind(&state)
        .fetch_one(&pool)
        .await
        .unwrap();

    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": base,
        "sub": "user-xyz",
        "aud": "tim-client",
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
    });
    let bad_id_token = sign_id_token(&bad_pem, &claims, kid);
    let token_body = json!({
        "access_token": "x",
        "id_token": bad_id_token,
        "token_type": "Bearer",
        "expires_in": 60,
    })
    .to_string();
    let _m_tok = server
        .mock("POST", "/token")
        .with_status(200)
        .with_body(&token_body)
        .expect(1)
        .create_async()
        .await;

    let (s, _body) = get_json(
        &router,
        &format!("/auth/callback/mock?code=any-code&state={state}"),
    )
    .await;
    // finding 01 fix: bad signature must fail — 422 Unprocessable.
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

// finding: token endpoint auth method. TARA (and OIDC Core §9 as the default when the
// client registration is silent) requires HTTP Basic. The pre-fix behaviour posted
// client_id/client_secret as form fields, which TARA rejected with 401 invalid_client and
// no existing test caught it because the token mock accepted every request shape. This
// asserts both sides: header present with the right value, credentials absent from body.
#[tokio::test]
async fn token_exchange_uses_http_basic_and_omits_credentials_from_form_body() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "idp-kid-1";

    let discovery_body = json!({
        "issuer": base.clone(),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
    })
    .to_string();
    let _m_disc = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&discovery_body)
        .expect_at_least(1)
        .create_async()
        .await;
    let jwks_body = json!({ "keys": [ jwk_from_public(&pk, kid) ] }).to_string();
    let _m_jwks = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&jwks_body)
        .expect_at_least(1)
        .create_async()
        .await;

    let Some(router) = setup_with_provider(&base).await else {
        return;
    };
    let (_s, body) = get_json(&router, "/auth/login/mock").await;
    let state = body["state"].as_str().unwrap().to_string();
    let db_url = std::env::var("TIM_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
    let (nonce,): (String,) = sqlx::query_as("SELECT nonce FROM auth.oauth_state WHERE state = $1")
        .bind(&state)
        .fetch_one(&pool)
        .await
        .unwrap();

    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": base.clone(),
        "sub": "user-xyz",
        "aud": "tim-client",
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
    });
    let id_token = sign_id_token(&pem, &claims, kid);
    let token_body = json!({
        "access_token": "x",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 60,
    })
    .to_string();

    let expected_basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(b"tim-client:shhh")
    );
    // Body regex is anchored — appending `&client_id=...&client_secret=...` (the pre-fix
    // behaviour) breaks the match and mockito returns 501, which surfaces as a 502
    // callback and fails the OK assertion below.
    let m_tok = server
        .mock("POST", "/token")
        .match_header("authorization", expected_basic.as_str())
        .match_body(mockito::Matcher::Regex(
            r"^grant_type=authorization_code&code=any-code(?:&redirect_uri=[^&]+)?(?:&code_verifier=[^&]+)?$".into(),
        ))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&token_body)
        .expect(1)
        .create_async()
        .await;

    let (s, body) = get_json(
        &router,
        &format!("/auth/callback/mock?code=any-code&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "callback body: {body:?}");
    m_tok.assert_async().await;
}

// finding: token exchange non-2xx path. Confirms the callback surfaces a 502 (and does not
// panic on `resp.text()` for the error body) when the token endpoint reports an OAuth2
// error response. The response body is deliberately non-empty so that if the fix later
// changed to require valid JSON, we'd notice.
#[tokio::test]
async fn callback_returns_bad_gateway_when_token_endpoint_reports_error() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, _pem) = generate_idp_keypair();
    let kid = "idp-kid-1";

    let discovery_body = json!({
        "issuer": base.clone(),
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
    })
    .to_string();
    let _m_disc = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_body(&discovery_body)
        .expect_at_least(1)
        .create_async()
        .await;
    let jwks_body = json!({ "keys": [ jwk_from_public(&pk, kid) ] }).to_string();
    let _m_jwks = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_body(&jwks_body)
        .expect_at_least(1)
        .create_async()
        .await;

    let Some(router) = setup_with_provider(&base).await else {
        return;
    };
    let (_s, body) = get_json(&router, "/auth/login/mock").await;
    let state = body["state"].as_str().unwrap().to_string();

    let _m_tok = server
        .mock("POST", "/token")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":"invalid_client","error_description":"pinned diagnostic"}"#)
        .expect(1)
        .create_async()
        .await;

    let (s, _body) = get_json(
        &router,
        &format!("/auth/callback/mock?code=any-code&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn callback_bubbles_idp_error_param() {
    // No mocks needed — the error path never contacts the IdP.
    let mut server = mockito::Server::new_async().await;
    let _m = server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_body(
            json!({
                "issuer": server.url(),
                "authorization_endpoint": format!("{}/authorize", server.url()),
                "token_endpoint": format!("{}/token", server.url()),
                "jwks_uri": format!("{}/jwks", server.url()),
                "grant_types_supported": ["authorization_code"],
                "response_types_supported": ["code"],
            })
            .to_string(),
        )
        .create_async()
        .await;
    let Some(router) = setup_with_provider(&server.url()).await else {
        return;
    };
    let (s, body) = get_json(
        &router,
        "/auth/callback/mock?error=access_denied&error_description=user+cancelled",
    )
    .await;
    // finding 04 fix: 400 with structured error rather than
    // "missing field `code`".
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "access_denied");
}
