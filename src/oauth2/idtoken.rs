//! OIDC ID-token verification — fixes findings 01, 02, 07.
//!
//! Validates in order (per OIDC Core §3.1.3.7):
//! 1. Header parses; `alg` is RS256/RS384/RS512/ES256/ES384/PS256/PS384/PS512
//!    (any signing alg the provider's JWKS keys advertise). `alg=none`
//!    is refused unconditionally.
//! 2. `kid` (if present) → JWKS lookup; else first key of matching
//!    `alg`.
//! 3. Signature verifies against the resolved key.
//! 4. `iss` equals `discovery.issuer` (exact match).
//! 5. `aud` contains the configured `client_id`.
//! 6. `exp` > now.
//! 7. `nbf`, if present, <= now.
//! 8. `iat` within `clock_skew_seconds` of now (future dates
//!    rejected).
//! 9. `nonce` MUST be present and MUST equal the value TIM stored in
//!    `auth.oauth_state` for this login. Absent nonce = rejected.

use std::collections::HashMap;

use chrono::Utc;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::error::{Result, TimError};
use crate::oauth2::discovery::Discovery;
use crate::oauth2::jwks::JwksCache;
use crate::oauth2::registry::Provider;

/// Claims we care about. `#[serde(flatten)] extra` catches everything
/// else so callers can extract e.g. `email`, `given_name`.
#[derive(Debug, Deserialize)]
pub struct IdTokenClaims {
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub aud: AudClaim,
    pub exp: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    pub iat: i64,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// `aud` per RFC 7519 §4.1.3 may be a string or an array of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AudClaim {
    Single(String),
    Multi(Vec<String>),
}

impl Default for AudClaim {
    fn default() -> Self {
        AudClaim::Multi(Vec::new())
    }
}

impl AudClaim {
    pub fn contains(&self, want: &str) -> bool {
        match self {
            AudClaim::Single(s) => s == want,
            AudClaim::Multi(v) => v.iter().any(|s| s == want),
        }
    }
}

pub struct Verified {
    pub claims: IdTokenClaims,
}

/// Full validation. `expected_nonce` is the nonce TIM stored at login
/// time — MUST match the token's `nonce` claim. Returns owned claims
/// so the caller can extract profile info.
pub async fn verify(
    jwks: &JwksCache,
    discovery: &Discovery,
    provider: &Provider,
    id_token: &str,
    expected_nonce: &str,
) -> Result<Verified> {
    // Header + kid pass without touching claims. `decode_header` also
    // refuses `alg = none`.
    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|e| TimError::Unprocessable(format!("id_token header: {e}")))?;
    if header.alg == Algorithm::HS256
        || header.alg == Algorithm::HS384
        || header.alg == Algorithm::HS512
    {
        return Err(TimError::Unprocessable(
            "id_token signed with a symmetric algorithm; refused".into(),
        ));
    }

    let set = jwks.fetch(&discovery.jwks_uri).await?;
    let key: &Jwk = match header.kid.as_deref() {
        Some(kid) => set
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .ok_or_else(|| {
                TimError::Unprocessable(format!("id_token kid \"{kid}\" not in JWKS"))
            })?,
        None => {
            // Fall back to first key matching alg — OIDC providers that
            // omit `kid` usually have exactly one signing key.
            set.keys
                .iter()
                .find(|k| jwk_matches_alg(k, header.alg))
                .ok_or_else(|| {
                    TimError::Unprocessable(
                        "id_token header omits kid and no JWKS key matches alg".into(),
                    )
                })?
        }
    };

    let decoding = decoding_key_for(key)?;

    // We do most claim validation ourselves so we can produce
    // TIM-shaped errors. jsonwebtoken enforces sig + exp + nbf; we add
    // iss, aud, iat-skew, and mandatory nonce.
    let mut v = Validation::new(header.alg);
    v.validate_exp = true;
    v.validate_nbf = true;
    v.validate_aud = false; // done manually against provider.client_id
    v.leeway = provider.config.token_validation.clock_skew_seconds;
    v.required_spec_claims.clear();
    v.required_spec_claims.insert("exp".into());
    v.required_spec_claims.insert("iat".into());
    v.required_spec_claims.insert("iss".into());
    v.required_spec_claims.insert("sub".into());
    v.set_issuer(&[&discovery.issuer]);

    let decoded = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding, &v)
        .map_err(|e| TimError::Unprocessable(format!("id_token verify: {e}")))?;
    let claims = decoded.claims;

    // aud MUST contain the client_id we authenticated with.
    if !claims.aud.contains(&provider.client_id) {
        return Err(TimError::Unprocessable(
            "id_token aud does not contain client_id".into(),
        ));
    }

    // iat future-date guard (jsonwebtoken doesn't check iat by
    // default; leeway covers exp/nbf only).
    let now = Utc::now().timestamp();
    let skew = provider.config.token_validation.clock_skew_seconds as i64;
    if claims.iat > now + skew {
        return Err(TimError::Unprocessable(
            "id_token iat is in the future beyond configured clock skew".into(),
        ));
    }

    // Nonce is MANDATORY — TIM always includes it in the authz
    // request, therefore the ID token MUST echo it.
    let token_nonce = claims
        .nonce
        .as_deref()
        .ok_or_else(|| TimError::Unprocessable("id_token nonce missing".into()))?;
    if !constant_time_eq(token_nonce.as_bytes(), expected_nonce.as_bytes()) {
        return Err(TimError::Unprocessable("id_token nonce mismatch".into()));
    }

    Ok(Verified { claims })
}

fn jwk_matches_alg(jwk: &Jwk, alg: Algorithm) -> bool {
    // If the JWK carries an `alg`, require exact match; otherwise
    // allow if kty is compatible with the header alg family.
    if let Some(k) = &jwk.common.key_algorithm {
        let k_str = format!("{k:?}");
        return k_str == format!("{alg:?}");
    }
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => matches!(
            alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::PS256
                | Algorithm::PS384
                | Algorithm::PS512
        ),
        AlgorithmParameters::EllipticCurve(_) => matches!(alg, Algorithm::ES256 | Algorithm::ES384),
        _ => false,
    }
}

fn decoding_key_for(jwk: &Jwk) -> Result<DecodingKey> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
            .map_err(|e| TimError::Unprocessable(format!("JWK → RSA decoding key: {e}"))),
        AlgorithmParameters::EllipticCurve(ec) => DecodingKey::from_ec_components(&ec.x, &ec.y)
            .map_err(|e| TimError::Unprocessable(format!("JWK → EC decoding key: {e}"))),
        other => Err(TimError::Unprocessable(format!(
            "unsupported JWK type: {other:?}"
        ))),
    }
}

/// `subtle::ConstantTimeEq` on byte slices of equal length; falls back
/// to `false` for length mismatch. Fine because nonces are constant
/// length in our issue path (`random_hex(32)` → 64 chars).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Re-used by the callback: given claims + provider mappings, build
/// a canonical profile map + user_id string.
///
/// Mapping lookup order for a `provider_key`:
///   1. RFC 7519 registered names (`sub`, `iss`) — captured as
///      explicit fields on `IdTokenClaims`, so `extra` does not
///      contain them.
///   2. Fall back to `claims.extra` for anything else (custom
///      provider claims like `given_name`, `family_name`, `acr`,
///      `amr`, `email`, ...).
///
/// TARA (and any provider that emits identity in a registered
/// claim — the personal code lives in `sub`) MUST be able to
/// reach `sub` from the mapping; the initial implementation only
/// looked in `extra` and silently returned nothing for
/// `personal_code: "sub"`.
/// Resolve a claim name, walking `.`-separated segments into nested objects.
///
/// A name without a dot is a plain top-level lookup, so providers that put claims at the top
/// level behave exactly as before. TARA carries the names under `profile_attributes`, and
/// without this a mapping of `profile_attributes.given_name` resolves to nothing and the
/// profile comes back with empty names.
///
/// There is no fallback between the two forms: a dotted path that does not exist yields None
/// rather than quietly matching a top-level claim with the same trailing name.
fn resolve_claim_path(
    extra: &HashMap<String, serde_json::Value>,
    path: &str,
) -> Option<serde_json::Value> {
    let mut segments = path.split('.');
    let mut current = extra.get(segments.next()?)?;
    for segment in segments {
        current = current.as_object()?.get(segment)?;
    }
    Some(current.clone())
}

pub fn profile_from_claims(
    provider: &Provider,
    claims: &IdTokenClaims,
) -> (String, HashMap<String, serde_json::Value>) {
    let mut profile = HashMap::new();
    for (canonical, provider_key) in &provider.config.claim_mappings {
        let v = match provider_key.as_str() {
            "sub" => Some(serde_json::Value::String(claims.sub.clone())),
            "iss" => Some(serde_json::Value::String(claims.iss.clone())),
            // aud is Single|Multi; expose as JSON array for uniformity
            // with providers that ship arrays.
            "aud" => Some(match &claims.aud {
                AudClaim::Single(s) => serde_json::json!([s]),
                AudClaim::Multi(v) => serde_json::json!(v),
            }),
            _ => resolve_claim_path(&claims.extra, provider_key),
        };
        if let Some(v) = v {
            profile.insert(canonical.clone(), v);
        }
    }
    (claims.sub.clone(), profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_strings() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn aud_claim_contains_matches_single_and_multi() {
        let single = AudClaim::Single("client-1".into());
        assert!(single.contains("client-1"));
        assert!(!single.contains("client-2"));
        let multi = AudClaim::Multi(vec!["a".into(), "b".into()]);
        assert!(multi.contains("b"));
        assert!(!multi.contains("c"));
    }

    // End-to-end signature tests generate a keypair, produce a signed
    // token, expose a mock JWKS, and route through `verify`. Lives in
    // `tests/it_oauth2_callback.rs` (finding 01 was masked because no
    // such test existed).

    fn tara_extra() -> HashMap<String, serde_json::Value> {
        // Shaped like a real TARA id_token: names only under profile_attributes.
        serde_json::from_value(serde_json::json!({
            "acr": "high",
            "profile_attributes": {
                "given_name": "MARY ÄNN",
                "family_name": "O’CONNEŽ-ŠUSLIK",
                "date_of_birth": "2000-01-01"
            }
        }))
        .unwrap()
    }

    #[test]
    fn dotted_path_reads_nested_claim() {
        let e = tara_extra();
        assert_eq!(
            resolve_claim_path(&e, "profile_attributes.given_name"),
            Some(serde_json::Value::String("MARY ÄNN".into()))
        );
    }

    #[test]
    fn undotted_name_still_reads_top_level() {
        let e = tara_extra();
        assert_eq!(
            resolve_claim_path(&e, "acr"),
            Some(serde_json::Value::String("high".into()))
        );
    }

    #[test]
    fn missing_path_does_not_fall_back_to_trailing_name() {
        let e = tara_extra();
        // `acr` exists at the top level; the dotted form must not find it anyway.
        assert_eq!(resolve_claim_path(&e, "profile_attributes.acr"), None);
        assert_eq!(resolve_claim_path(&e, "nope.given_name"), None);
        // Walking into a non-object is a miss, not a panic.
        assert_eq!(resolve_claim_path(&e, "acr.given_name"), None);
    }
}
