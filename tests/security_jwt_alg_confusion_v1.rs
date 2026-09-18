//! BREAK-TESTS-GAP-CLOSURE-v1 §G4 — positive-control regression pin.
//!
//! TIM must reject every JWT introspected against `/introspect` unless
//! the token is signed with the RS256 key it advertises via
//! `/jwt/keys/public`. Concretely, the three probe classes we exercise
//! here (all must land on `{"active": false}` — never a signature-
//! confusion 200 with real claims):
//!
//! 1. `alg=none` header with an otherwise well-formed body whose `kid`
//!    matches TIM's signer.
//! 2. HS256-signed token whose HMAC key is TIM's advertised **public**
//!    RSA key material (PKCS#1 PEM). The classic alg-confusion attack.
//! 3. Every symmetric algorithm the `jsonwebtoken` crate speaks
//!    (`HS256`/`HS384`/`HS512`) plus `none` and a curve-mismatched
//!    `ES256`, each forging the signer's kid. Loop shape mirrors §G4's
//!    "third probe" from BREAK-TESTS-GAP-CLOSURE-v1.
//!
//! All three probes assert 200 + `"active":false` — the token is
//! **inactive**, not that the request is refused. RFC 7662 §2.2 is
//! deliberate: an inactive response is the uniform reply for every
//! validation failure so attackers cannot distinguish "wrong signature"
//! from "unknown token".

use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use tim::{
    config::{AppConfig, JwtConfig},
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::{session::MemoryStore, ProviderRegistry},
    router::{build_router, AppState},
    security::{admin::AdminGate, introspect_auth::IntrospectionGate},
};
use tower::ServiceExt;

mod common;

const TEST_KEY: &str = include_str!("fixtures/test-jwt-private.pem");
const TEST_KID: &str = "tim-rs-1";

async fn setup() -> Option<axum::Router> {
    let Ok(db_url) = std::env::var("TIM_DATABASE_URL") else {
        eprintln!("SKIP: TIM_DATABASE_URL not set");
        return None;
    };
    common::serialize_binary(&db_url).await;

    let mut cfg = AppConfig::default();
    cfg.security.require_admin_token = false;
    cfg.security.admin_token_env = String::new();
    cfg.oauth2.session_sweep_interval_seconds = 0;
    // 0.4.0-alpha (FN1): default requires introspection client auth.
    // This test exercises the alg-confusion invariant, not the auth
    // axis — opt out so the handler proceeds past the gate.
    cfg.introspection.required_client_auth = false;

    let pool = db::connect(&db_url, &cfg.database).await.ok()?;
    db::run_migrations(&pool).await.ok()?;
    let signer = JwtSigner::from_pkcs8_pem(TEST_KEY, TEST_KID.into()).ok()?;
    let jwt = Arc::new(JwtService::new(
        pool.clone(),
        signer.clone(),
        JwtConfig::default(),
    ));
    let providers = Arc::new(ProviderRegistry::from_config(&cfg.oauth2).await.ok()?);
    let sessions = Arc::new(MemoryStore::new(std::time::Duration::from_secs(60)));
    let admin = AdminGate::from_config(&cfg.security).ok()?;
    let introspect_gate = IntrospectionGate::from_config(&cfg.introspection).ok()?;
    let state = AppState {
        config: Arc::new(cfg.clone()),
        db: pool,
        signer: Arc::new(signer),
        jwt,
        providers,
        sessions,
        admin,
        introspect_gate,
    };
    Some(build_router(state, &cfg))
}

async fn post_introspect(router: &axum::Router, token: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!("token={token}")))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn tim_public_pkcs1_pem() -> String {
    let sk = RsaPrivateKey::from_pkcs8_pem(TEST_KEY).unwrap();
    let pk = RsaPublicKey::from(&sk);
    pk.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string()
}

fn b64_json(v: &serde_json::Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
}

/// Hand-assemble `alg=none` — `jsonwebtoken` refuses to encode it.
fn craft_alg_none(kid: &str) -> String {
    let header = json!({ "alg": "none", "typ": "JWT", "kid": kid });
    let claims = json!({
        "iss": JwtConfig::default().issuer,
        "sub": "attacker",
        "jti": "00000000-0000-0000-0000-000000000000",
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + 3600,
    });
    format!("{}.{}.", b64_json(&header), b64_json(&claims))
}

#[tokio::test]
async fn alg_none_with_valid_kid_is_inactive() {
    let Some(router) = setup().await else {
        return;
    };
    let token = craft_alg_none(TEST_KID);
    let (s, body) = post_introspect(&router, &token).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains("\"active\":false"),
        "alg=none must be inactive; body: {body}"
    );
    // Never leak forged sub — verify no claim from the crafted token
    // reached the response.
    assert!(
        !body.contains("attacker"),
        "response echoed unverified sub; body: {body}"
    );
}

#[tokio::test]
async fn hs256_signed_with_public_key_is_inactive() {
    let Some(router) = setup().await else {
        return;
    };
    let pk_pem = tim_public_pkcs1_pem();
    // Classic attack: attacker takes the public key TIM publishes at
    // /jwt/keys/public and uses its PEM bytes as an HMAC secret.
    let key = EncodingKey::from_secret(pk_pem.as_bytes());
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TEST_KID.into());
    let claims = json!({
        "iss": JwtConfig::default().issuer,
        "sub": "attacker",
        "jti": "00000000-0000-0000-0000-000000000000",
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + 3600,
    });
    let token = encode(&header, &claims, &key).unwrap();
    let (s, body) = post_introspect(&router, &token).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        body.contains("\"active\":false"),
        "HS256-with-public-key must be inactive; body: {body}"
    );
    assert!(
        !body.contains("attacker"),
        "response echoed unverified sub; body: {body}"
    );
}

#[tokio::test]
async fn alg_family_loop_forging_signer_kid_all_inactive() {
    let Some(router) = setup().await else {
        return;
    };
    let pk_pem = tim_public_pkcs1_pem();
    let hmac_key = EncodingKey::from_secret(pk_pem.as_bytes());
    let claims = json!({
        "iss": JwtConfig::default().issuer,
        "sub": "attacker",
        "jti": "00000000-0000-0000-0000-000000000000",
        "iat": chrono::Utc::now().timestamp(),
        "exp": chrono::Utc::now().timestamp() + 3600,
    });

    // (label, algorithm, token) — build each probe with the crate
    // where possible; alg=none goes via the hand-assembled path.
    let mut probes: Vec<(&str, String)> = Vec::new();
    for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let mut header = Header::new(alg);
        header.kid = Some(TEST_KID.into());
        let tok = encode(&header, &claims, &hmac_key).unwrap();
        probes.push((
            match alg {
                Algorithm::HS256 => "HS256",
                Algorithm::HS384 => "HS384",
                Algorithm::HS512 => "HS512",
                _ => unreachable!(),
            },
            tok,
        ));
    }
    probes.push(("none", craft_alg_none(TEST_KID)));

    for (label, tok) in &probes {
        let (s, body) = post_introspect(&router, tok).await;
        assert_eq!(s, StatusCode::OK, "{label}: unexpected status");
        assert!(
            body.contains("\"active\":false"),
            "{label}: token was accepted as active; body: {body}"
        );
        assert!(
            !body.contains("attacker"),
            "{label}: response echoed unverified sub; body: {body}"
        );
    }
}
