use std::path::Path;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use jsonwebtoken::errors::ErrorKind as JwtErrorKind;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData,
    Validation,
};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::error::{Result, TimError};

/// A loaded RSA keypair used to sign and verify RS256 JWTs.
///
/// Loaded once at startup from a PKCS#8 PEM file. The public half is
/// derived and exposed via JWKS. Supports an optional predecessor key
/// during a rotation grace period (F-PR-3, `book/src/how-to/
/// rotate-signing-key.md`): the current key is used for every new
/// signature and appears in JWKS; the previous key appears in JWKS and
/// is accepted for verification until `retires_at` passes.
#[derive(Clone)]
pub struct JwtSigner {
    current: Arc<KeyPair>,
    previous: Option<Arc<KeyPair>>,
    previous_retires_at: Option<DateTime<Utc>>,
}

struct KeyPair {
    kid: String,
    encoding: EncodingKey,
    decoding: DecodingKey,
    public: RsaPublicKey,
}

impl JwtSigner {
    pub fn load_from_pem(path: &Path, kid: String) -> Result<Self> {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| TimError::Crypto(format!("read {}: {e}", path.display())))?;
        Self::from_pkcs8_pem(&pem, kid)
    }

    pub fn from_pkcs8_pem(pem: &str, kid: String) -> Result<Self> {
        let current = Arc::new(KeyPair::from_pkcs8_pem(pem, kid)?);
        Ok(Self {
            current,
            previous: None,
            previous_retires_at: None,
        })
    }

    /// Attach a retiring predecessor key, active for verification and
    /// JWKS emission until `retires_at`. Signing continues to use the
    /// current key. Returns an error if the previous kid equals the
    /// current kid — collision would make JWKS `kid` disambiguation
    /// impossible on downstream verifiers.
    pub fn with_previous(
        mut self,
        pem: &str,
        kid: String,
        retires_at: DateTime<Utc>,
    ) -> Result<Self> {
        if kid == self.current.kid {
            return Err(TimError::Config(format!(
                "jwt.previous_key.key_id must differ from jwt.key_id (`{kid}`)"
            )));
        }
        let prev = Arc::new(KeyPair::from_pkcs8_pem(pem, kid)?);
        self.previous = Some(prev);
        self.previous_retires_at = Some(retires_at);
        Ok(self)
    }

    /// Load a previous key from a PEM file. Convenience wrapper over
    /// `with_previous` for the `main::serve` boot path.
    pub fn load_previous_from_pem(
        self,
        path: &Path,
        kid: String,
        retires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| TimError::Crypto(format!("read {}: {e}", path.display())))?;
        self.with_previous(&pem, kid, retires_at)
    }

    /// Current kid — the one used to sign new tokens.
    pub fn kid(&self) -> &str {
        &self.current.kid
    }

    /// Predecessor kid + retirement instant if a rotation grace period
    /// is configured AND still active (retires_at > now).
    pub fn previous_kid_active(&self) -> Option<(&str, DateTime<Utc>)> {
        let retires = self.previous_retires_at?;
        if retires <= Utc::now() {
            return None;
        }
        let prev = self.previous.as_ref()?;
        Some((&prev.kid, retires))
    }

    /// Predecessor retirement instant regardless of activity — used by
    /// doctor / boot WARN so operators see the state even after the
    /// grace period expires.
    pub fn previous_retires_at(&self) -> Option<DateTime<Utc>> {
        self.previous_retires_at
    }

    pub fn sign<C: Serialize>(&self, claims: &C) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.current.kid.clone());
        encode(&header, claims, &self.current.encoding)
            .map_err(|e| TimError::Crypto(format!("sign JWT: {e}")))
    }

    /// Decode + verify signature and standard claims. Caller-provided
    /// `Validation` controls what is checked (exp, aud, iss, ...).
    ///
    /// During a rotation grace period, if signature verification against
    /// the current key fails with `InvalidSignature`, the previous key
    /// is tried before the error is surfaced. Any other failure mode
    /// (expired, malformed, wrong issuer) is returned from the first
    /// attempt — no second attempt would change the outcome.
    pub fn verify<C: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<TokenData<C>> {
        self.verify_raw(token, validation)
            .map_err(|e| TimError::Crypto(format!("verify JWT: {e}")))
    }

    /// Like `verify` but returns the raw `jsonwebtoken` error so
    /// callers can classify via `error.kind()` for stable monitoring
    /// codes. Wrapping the error into `TimError::Crypto(String)`
    /// discarded the typed kind and forced string-matching downstream.
    ///
    /// Two-key fallback path: on `InvalidSignature` from the current
    /// key, try the previous key iff it exists AND retires_at > now.
    pub fn verify_raw<C: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> std::result::Result<TokenData<C>, jsonwebtoken::errors::Error> {
        // Route via kid when available so we skip a doomed signature
        // check on obviously wrong-key tokens. Falls through to
        // "try current first" when the header has no kid.
        if let Ok(header) = decode_header(token) {
            if let Some(kid) = header.kid.as_deref() {
                if let Some(prev) = self.active_previous_matching(kid) {
                    return decode::<C>(token, &prev.decoding, validation);
                }
                // kid != current AND no matching previous → fall through
                // so the current key's Invalid* error is what's returned.
            }
        }
        match decode::<C>(token, &self.current.decoding, validation) {
            Ok(d) => Ok(d),
            Err(e) => match e.kind() {
                JwtErrorKind::InvalidSignature => {
                    if let Some(prev) = self.active_previous() {
                        decode::<C>(token, &prev.decoding, validation)
                    } else {
                        Err(e)
                    }
                }
                _ => Err(e),
            },
        }
    }

    fn active_previous(&self) -> Option<&Arc<KeyPair>> {
        let retires = self.previous_retires_at?;
        if retires <= Utc::now() {
            return None;
        }
        self.previous.as_ref()
    }

    fn active_previous_matching(&self, kid: &str) -> Option<&Arc<KeyPair>> {
        let prev = self.active_previous()?;
        (prev.kid == kid).then_some(prev)
    }

    /// Peek at the header without verifying — used by introspection
    /// to route by `kid` / algorithm.
    pub fn header_of(token: &str) -> Result<Header> {
        decode_header(token).map_err(|e| TimError::Crypto(format!("decode header: {e}")))
    }

    /// Emit a JWK Set advertising the public key(s). During an active
    /// rotation grace period this returns two keys — current + previous
    /// — so downstream verifiers can accept tokens signed by either.
    /// After `previous.retires_at` passes, only the current key remains.
    pub fn jwks(&self) -> serde_json::Value {
        let mut keys = vec![self.current.jwk_json()];
        if let Some(prev) = self.active_previous() {
            keys.push(prev.jwk_json());
        }
        serde_json::json!({ "keys": keys })
    }

    /// Emit the public key of the current signing key as a PKCS#1 PEM
    /// string.
    ///
    /// Used by the legacy JVM 1.x `/jwt/verification-key` compat
    /// endpoint (matrix row E01). Single-key by design — legacy Java
    /// consumers cannot pick between candidates and must migrate to
    /// `/jwt/keys/public` for the multi-key JWKS shape during a
    /// rotation grace period.
    pub fn public_pem(&self) -> Result<String> {
        self.current
            .public
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map(|p| p.to_string())
            .map_err(|e| TimError::Crypto(format!("encode public PKCS#1 PEM: {e}")))
    }
}

impl KeyPair {
    fn from_pkcs8_pem(pem: &str, kid: String) -> Result<Self> {
        let private = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| TimError::Crypto(format!("parse PKCS#8 PEM: {e}")))?;
        let public = RsaPublicKey::from(&private);
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| TimError::Crypto(format!("jsonwebtoken encoding key: {e}")))?;
        // Derive PKCS#1 PEM for decoding side. jsonwebtoken accepts
        // PKCS#1 or SPKI here; we round-trip to keep both halves in
        // sync with what JWKS advertises.
        let public_pem = public
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| TimError::Crypto(format!("encode public PKCS#1: {e}")))?;
        let decoding = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| TimError::Crypto(format!("jsonwebtoken decoding key: {e}")))?;
        Ok(Self {
            kid,
            encoding,
            decoding,
            public,
        })
    }

    fn jwk_json(&self) -> serde_json::Value {
        let n = URL_SAFE_NO_PAD.encode(self.public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(self.public.e().to_bytes_be());
        serde_json::json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": self.kid,
            "n": n,
            "e": e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// A 2048-bit RSA private key generated once for tests. Committed
    /// deliberately — this key is public and MUST NOT be used for
    /// anything but this test suite.
    const TEST_KEY: &str = include_str!("../../tests/fixtures/test-jwt-private.pem");
    /// A second distinct 2048-bit RSA private key for rotation tests.
    /// Same discipline — test-only, never for production signing.
    const TEST_KEY_ALT: &str = include_str!("../../tests/fixtures/test-jwt-private-alt.pem");

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Claims {
        sub: String,
        exp: usize,
        iss: String,
    }

    fn claims(iss: &str) -> Claims {
        Claims {
            sub: "user-42".into(),
            exp: (chrono::Utc::now().timestamp() + 60) as usize,
            iss: iss.into(),
        }
    }

    fn signer() -> JwtSigner {
        JwtSigner::from_pkcs8_pem(TEST_KEY, "test-kid".into()).unwrap()
    }

    #[test]
    fn round_trip_sign_verify() {
        let s = signer();
        let token = s.sign(&claims("TIM-TEST")).unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&["TIM-TEST"]);
        v.validate_aud = false;
        let decoded: TokenData<Claims> = s.verify(&token, &v).unwrap();
        assert_eq!(decoded.claims.sub, "user-42");
    }

    #[test]
    fn jwks_contains_kid_and_alg() {
        let s = signer();
        let j = s.jwks();
        let key = &j["keys"][0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["kid"], "test-kid");
        assert!(key["n"].as_str().unwrap().len() > 100);
        assert_eq!(key["e"], "AQAB");
    }

    #[test]
    fn expired_token_fails_verification() {
        let s = signer();
        let c = Claims {
            sub: "u".into(),
            exp: 1,
            iss: "TIM-TEST".into(),
        };
        let token = s.sign(&c).unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.validate_aud = false;
        let err = s.verify::<Claims>(&token, &v).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("verify") || msg.contains("Expired"));
    }

    // --- Rotation-with-grace-period tests (F-PR-3, T-7) ---

    fn future_days(n: i64) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::days(n)
    }
    fn past_days(n: i64) -> DateTime<Utc> {
        Utc::now() - chrono::Duration::days(n)
    }

    #[test]
    fn with_previous_rejects_matching_kid() {
        let s = JwtSigner::from_pkcs8_pem(TEST_KEY, "same".into()).unwrap();
        // JwtSigner is not Debug (RSA / EncodingKey types below it
        // aren't), so `.unwrap_err()` doesn't type-check; match on the
        // Result directly.
        match s.with_previous(TEST_KEY_ALT, "same".into(), future_days(7)) {
            Ok(_) => panic!("expected error on matching kid"),
            Err(e) => assert!(matches!(e, TimError::Config(_))),
        }
    }

    #[test]
    fn jwks_emits_two_keys_during_grace() {
        let s = JwtSigner::from_pkcs8_pem(TEST_KEY, "current".into())
            .unwrap()
            .with_previous(TEST_KEY_ALT, "previous".into(), future_days(7))
            .unwrap();
        let j = s.jwks();
        let keys = j["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2, "current + previous during grace");
        assert_eq!(keys[0]["kid"], "current");
        assert_eq!(keys[1]["kid"], "previous");
    }

    #[test]
    fn jwks_emits_only_current_after_retirement() {
        let s = JwtSigner::from_pkcs8_pem(TEST_KEY, "current".into())
            .unwrap()
            .with_previous(TEST_KEY_ALT, "previous".into(), past_days(1))
            .unwrap();
        let j = s.jwks();
        let keys = j["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1, "previous dropped once retires_at passed");
        assert_eq!(keys[0]["kid"], "current");
    }

    #[test]
    fn verify_accepts_token_signed_with_previous_key_during_grace() {
        // Simulate: a token was signed with what is now the "previous"
        // key. During rotation grace the verifier must still accept it.
        let previous_signer = JwtSigner::from_pkcs8_pem(TEST_KEY_ALT, "previous".into()).unwrap();
        let token = previous_signer.sign(&claims("TIM-TEST")).unwrap();

        let s = JwtSigner::from_pkcs8_pem(TEST_KEY, "current".into())
            .unwrap()
            .with_previous(TEST_KEY_ALT, "previous".into(), future_days(7))
            .unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&["TIM-TEST"]);
        v.validate_aud = false;
        let decoded: TokenData<Claims> = s.verify(&token, &v).unwrap();
        assert_eq!(decoded.claims.sub, "user-42");
    }

    #[test]
    fn verify_rejects_previous_signed_token_after_retirement() {
        let previous_signer = JwtSigner::from_pkcs8_pem(TEST_KEY_ALT, "previous".into()).unwrap();
        let token = previous_signer.sign(&claims("TIM-TEST")).unwrap();

        let s = JwtSigner::from_pkcs8_pem(TEST_KEY, "current".into())
            .unwrap()
            // Grace period already ended one day ago.
            .with_previous(TEST_KEY_ALT, "previous".into(), past_days(1))
            .unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&["TIM-TEST"]);
        v.validate_aud = false;
        let err = s.verify::<Claims>(&token, &v).unwrap_err();
        // Any error is fine — the invariant is "rejected." Assert the
        // wrapper is TimError::Crypto so the surface stays uniform.
        assert!(matches!(err, TimError::Crypto(_)));
    }

    #[test]
    fn sign_always_uses_current_key_even_during_grace() {
        let s = JwtSigner::from_pkcs8_pem(TEST_KEY, "current".into())
            .unwrap()
            .with_previous(TEST_KEY_ALT, "previous".into(), future_days(7))
            .unwrap();
        let token = s.sign(&claims("TIM-TEST")).unwrap();
        let header = JwtSigner::header_of(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("current"));
    }

    #[test]
    fn previous_kid_active_reflects_retires_at() {
        let s_active = JwtSigner::from_pkcs8_pem(TEST_KEY, "current".into())
            .unwrap()
            .with_previous(TEST_KEY_ALT, "previous".into(), future_days(3))
            .unwrap();
        assert!(s_active.previous_kid_active().is_some());

        let s_retired = JwtSigner::from_pkcs8_pem(TEST_KEY, "current".into())
            .unwrap()
            .with_previous(TEST_KEY_ALT, "previous".into(), past_days(1))
            .unwrap();
        assert!(s_retired.previous_kid_active().is_none());
        assert!(s_retired.previous_retires_at().is_some());
    }
}
