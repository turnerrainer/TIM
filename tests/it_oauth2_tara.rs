//! Task 007 — TARA (Estonian eID) integration tests against a mock IdP.
//!
//! Locks the Estonian-eID-specific claim shape end-to-end: personal
//! code, UTF-8 given/family name, `acr` / `amr`, and rejection of
//! malformed tokens. Uses mockito to simulate `tara-test.ria.ee`.

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

const TIM_KEY: &str = include_str!("fixtures/test-jwt-private.pem");
const TARA_CANONICAL: &str = include_str!("fixtures/tara-claims-canonical.json");

/// Setup a TIM-on-Rust router wired to a TARA-shaped mock provider.
/// `tara_test_issuer` should equal `server.url()` — the callback
/// verifier enforces `iss == discovery.issuer` and both must match
/// the JWT `iss` claim later.
async fn setup_tara(server_url: &str, clock_skew_seconds: u64) -> Option<axum::Router> {
    setup_tara_with_mappings(server_url, clock_skew_seconds, default_tara_mappings()).await
}

fn default_tara_mappings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("personal_code", "sub"),
        ("first_name", "given_name"),
        ("last_name", "family_name"),
        ("date_of_birth", "date_of_birth"),
        ("acr", "acr"),
        ("amr", "amr"),
    ]
}

async fn setup_tara_with_mappings(
    server_url: &str,
    clock_skew_seconds: u64,
    mappings: Vec<(&'static str, &'static str)>,
) -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;
    let pool = db::connect(&db_url, &tim::config::DatabaseConfig::default())
        .await
        .ok()?;
    db::run_migrations(&pool).await.ok()?;
    sqlx::query("TRUNCATE TABLE auth.oauth_state, auth.session")
        .execute(&pool)
        .await
        .ok()?;

    std::env::set_var("TARA_TEST_CLIENT_ID", "tim-tara-client");
    std::env::set_var("TARA_TEST_CLIENT_SECRET", "tara-shhh");

    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    // 0.4.0-alpha (FN1): introspection default is now on; this test
    // does not exercise it — opt out explicitly.
    cfg.introspection.required_client_auth = false;
    cfg.server.public_base_url = "https://tim.example.com".into();

    let mut provider = ProviderConfig {
        name: "TARA (test)".into(),
        discovery_url: format!("{server_url}/.well-known/openid-configuration"),
        client_id_env: "TARA_TEST_CLIENT_ID".into(),
        client_secret_env: "TARA_TEST_CLIENT_SECRET".into(),
        scopes: vec!["openid".into()],
        claim_mappings: Default::default(),
        token_validation: TokenValidationConfig {
            clock_skew_seconds,
            cache_ttl_seconds: 3600,
        },
        allowed_redirect_uris: vec!["https://tim.example.com/auth/callback/tara".into()],
        allow_http_discovery: true,
        jwks_uri: None,
    };
    for (canonical, provider_key) in mappings {
        provider
            .claim_mappings
            .insert(canonical.into(), provider_key.into());
    }
    cfg.oauth2.providers.insert("tara".into(), provider);

    let signer = JwtSigner::from_pkcs8_pem(TIM_KEY, "tara-it".into()).ok()?;
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
        introspect_gate: tim::security::IntrospectionGate::default(),
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

/// Load the canonical claim shape from the fixture and fill in
/// runtime-dependent values (exp, iat, nonce, iss).
fn tara_claims(iss: &str, nonce: &str, exp_offset: i64) -> Value {
    let mut v: Value = serde_json::from_str(TARA_CANONICAL).expect("parse fixture");
    let now = chrono::Utc::now().timestamp();
    v["iss"] = json!(iss);
    v["exp"] = json!(now + exp_offset);
    v["iat"] = json!(now);
    v["nonce"] = json!(nonce);
    v
}

async fn start_flow(router: &axum::Router) -> (String, String) {
    let (s, body) = get_json(router, "/auth/login/tara").await;
    assert_eq!(s, StatusCode::OK, "tara login failed: {body:?}");
    let state = body["state"].as_str().expect("state").to_string();
    let db_url = std::env::var("TIM_DATABASE_URL").unwrap();
    let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
    let (nonce,): (String,) = sqlx::query_as("SELECT nonce FROM auth.oauth_state WHERE state = $1")
        .bind(&state)
        .fetch_one(&pool)
        .await
        .unwrap();
    (state, nonce)
}

async fn mock_discovery(server: &mut mockito::ServerGuard, base: &str) -> mockito::Mock {
    let body = json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "grant_types_supported": ["authorization_code"],
        "response_types_supported": ["code"],
    })
    .to_string();
    server
        .mock("GET", "/.well-known/openid-configuration")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&body)
        .expect_at_least(1)
        .create_async()
        .await
}

async fn mock_jwks(
    server: &mut mockito::ServerGuard,
    pk: &RsaPublicKey,
    kid: &str,
) -> mockito::Mock {
    let body = json!({ "keys": [ jwk_from_public(pk, kid) ] }).to_string();
    server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&body)
        .expect_at_least(1)
        .create_async()
        .await
}

async fn mock_token(server: &mut mockito::ServerGuard, id_token: &str) -> mockito::Mock {
    let body = json!({
        "access_token": "opaque-access",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    })
    .to_string();
    server
        .mock("POST", "/token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(&body)
        .expect(1)
        .create_async()
        .await
}

// ---------------------------------------------------------------------------
// Test 1: happy path — Estonian personal code + UTF-8 name survive round-trip.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tara_callback_creates_session_with_estonian_personal_code() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "tara-kid-1";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, kid).await;

    let Some(router) = setup_tara(&base, 60).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    let claims = tara_claims(&base, &nonce, 300);
    let id_token = sign_id_token(&pem, &claims, kid);
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "callback body: {body:?}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["provider"], "tara");
    assert_eq!(body["user_profile"]["user_id"], "60001019906");
    assert_eq!(body["user_profile"]["personal_code"], "60001019906");
    // Estonian UTF-8 survived — no `?` fallback.
    assert_eq!(body["user_profile"]["first_name"], "Kärt");
    assert_eq!(body["user_profile"]["last_name"], "Ööbik");
    assert_eq!(body["user_profile"]["date_of_birth"], "1960-01-01");
}

// ---------------------------------------------------------------------------
// Test 2: `acr` + `amr` flow through as-typed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tara_acr_and_amr_flow_into_session_profile() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "tara-kid-1";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, kid).await;

    let Some(router) = setup_tara(&base, 60).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    let claims = tara_claims(&base, &nonce, 300);
    let id_token = sign_id_token(&pem, &claims, kid);
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "callback body: {body:?}");
    assert_eq!(body["user_profile"]["acr"], "high");
    // amr MUST remain an array, not a string.
    let amr = body["user_profile"]["amr"]
        .as_array()
        .expect("amr is array");
    assert_eq!(amr.len(), 1);
    assert_eq!(amr[0], "mID");
}

// ---------------------------------------------------------------------------
// Test 3: iss mismatch → 422.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tara_id_token_with_missing_iss_is_rejected() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "tara-kid-1";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, kid).await;

    let Some(router) = setup_tara(&base, 60).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    // Deliberately wrong issuer.
    let claims = tara_claims("https://wrong-issuer.example.com", &nonce, 300);
    let id_token = sign_id_token(&pem, &claims, kid);
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, _body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// Test 4: kid unknown in JWKS → 422.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tara_id_token_signed_with_wrong_kid_is_rejected() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let jwks_kid = "tara-kid-1";
    let token_kid = "tara-kid-UNKNOWN";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, jwks_kid).await;

    let Some(router) = setup_tara(&base, 60).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    let claims = tara_claims(&base, &nonce, 300);
    let id_token = sign_id_token(&pem, &claims, token_kid);
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, _body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// Test 5: alg=none is refused unconditionally.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tara_id_token_with_alg_none_is_rejected() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, _pem) = generate_idp_keypair();
    let kid = "tara-kid-1";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, kid).await;

    let Some(router) = setup_tara(&base, 60).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    let claims = tara_claims(&base, &nonce, 300);

    // Craft an unsigned token: header = {"alg":"none","typ":"JWT"},
    // payload = <base64 of claims>, signature empty.
    let header = json!({"alg": "none", "typ": "JWT"}).to_string();
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let id_token = format!("{header_b64}.{payload_b64}.");
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, _body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// Test 6: expired ID token is rejected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tara_expired_id_token_is_rejected() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "tara-kid-1";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, kid).await;

    // Tight clock skew so exp = now - 60 s is clearly past.
    let Some(router) = setup_tara(&base, 5).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    let claims = tara_claims(&base, &nonce, -60); // exp 60 s in the past
    let id_token = sign_id_token(&pem, &claims, kid);
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, _body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// Test 7: profile_attributes is not silently promoted to top-level.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tara_profile_attributes_are_not_flattened_into_top_level() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "tara-kid-1";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, kid).await;

    let Some(router) = setup_tara(&base, 60).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    // The canonical fixture already has profile_attributes.given_name =
    // "Ignored" alongside top-level given_name = "Kärt". Claim mapping
    // takes top-level, not nested.
    let claims = tara_claims(&base, &nonce, 300);
    let id_token = sign_id_token(&pem, &claims, kid);
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "callback body: {body:?}");
    // First name came from top-level `given_name`, NOT from
    // `profile_attributes.given_name`. If the mapping ever flattened
    // silently, first_name would be "Ignored".
    assert_eq!(body["user_profile"]["first_name"], "Kärt");
    assert_ne!(body["user_profile"]["first_name"], "Ignored");
}

// ---------------------------------------------------------------------------
// Test 8: dotted claim mapping resolves nested profile_attributes end-to-end.
// ---------------------------------------------------------------------------

// finding: nested claim mapping. TARA carries given_name/family_name only under
// profile_attributes, and the pre-fix flat lookup returned nothing for a dotted mapping.
// This is the seam that the resolve_claim_path unit tests do NOT exercise — it verifies
// profile_from_claims actually reads through resolve_claim_path when the mapping key is
// dotted. Uses the canonical fixture whose profile_attributes contain "Ignored" — a bug
// that fell back to top-level `given_name` would flip first_name to "Kärt", so the
// assertions pin the nested value specifically.
#[tokio::test]
async fn tara_dotted_mapping_resolves_nested_profile_attributes() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "tara-kid-1";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, kid).await;

    let mappings = vec![
        ("personal_code", "sub"),
        ("first_name", "profile_attributes.given_name"),
        ("last_name", "profile_attributes.family_name"),
    ];
    let Some(router) = setup_tara_with_mappings(&base, 60, mappings).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    let claims = tara_claims(&base, &nonce, 300);
    let id_token = sign_id_token(&pem, &claims, kid);
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "callback body: {body:?}");
    // Nested values, not the top-level "Kärt"/"Ööbik".
    assert_eq!(body["user_profile"]["first_name"], "Ignored");
    assert_eq!(body["user_profile"]["last_name"], "Ignored");
}

// finding: dotted-path miss must not fall through to a top-level claim with the same
// trailing segment. The fixture has both `given_name` at the top level and
// `profile_attributes.given_name` nested; if the mapping asks for a dotted path whose
// prefix does not exist, the result should be None (claim omitted from the profile), NOT
// the top-level `given_name`.
#[tokio::test]
async fn tara_dotted_mapping_miss_does_not_fall_back_to_top_level() {
    let mut server = mockito::Server::new_async().await;
    let base = server.url();
    let (_sk, pk, pem) = generate_idp_keypair();
    let kid = "tara-kid-1";

    let _disc = mock_discovery(&mut server, &base).await;
    let _jwks = mock_jwks(&mut server, &pk, kid).await;

    // `no_such_object.given_name` — first segment does not exist. The top-level
    // `given_name` MUST NOT be returned.
    let mappings = vec![
        ("personal_code", "sub"),
        ("first_name", "no_such_object.given_name"),
    ];
    let Some(router) = setup_tara_with_mappings(&base, 60, mappings).await else {
        return;
    };
    let (state, nonce) = start_flow(&router).await;
    let claims = tara_claims(&base, &nonce, 300);
    let id_token = sign_id_token(&pem, &claims, kid);
    let _tok = mock_token(&mut server, &id_token).await;

    let (s, body) = get_json(
        &router,
        &format!("/auth/callback/tara?code=any&state={state}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "callback body: {body:?}");
    assert!(
        body["user_profile"]["first_name"].is_null(),
        "first_name must be absent, got {:?}",
        body["user_profile"]["first_name"]
    );
}
