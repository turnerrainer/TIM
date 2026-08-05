use std::path::Path;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
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
/// Loaded once at startup from a PKCS#8 PEM file. The public half
/// is derived and exposed via JWKS.
#[derive(Clone)]
pub struct JwtSigner {
    inner: Arc<Inner>,
}

struct Inner {
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
            inner: Arc::new(Inner {
                kid,
                encoding,
                decoding,
                public,
            }),
        })
    }

    pub fn kid(&self) -> &str {
        &self.inner.kid
    }

    pub fn sign<C: Serialize>(&self, claims: &C) -> Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.inner.kid.clone());
        encode(&header, claims, &self.inner.encoding)
            .map_err(|e| TimError::Crypto(format!("sign JWT: {e}")))
    }

    /// Decode + verify signature and standard claims. Caller-provided
    /// `Validation` controls what is checked (exp, aud, iss, ...).
    pub fn verify<C: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
        validation: &Validation,
    ) -> Result<TokenData<C>> {
        decode::<C>(token, &self.inner.decoding, validation)
            .map_err(|e| TimError::Crypto(format!("verify JWT: {e}")))
    }

    /// Peek at the header without verifying — used by introspection
    /// to route by `kid` / algorithm.
    pub fn header_of(token: &str) -> Result<Header> {
        decode_header(token).map_err(|e| TimError::Crypto(format!("decode header: {e}")))
    }

    /// Emit a single-key JWK Set advertising the public key.
    pub fn jwks(&self) -> serde_json::Value {
        let n = URL_SAFE_NO_PAD.encode(self.inner.public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(self.inner.public.e().to_bytes_be());
        serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": self.inner.kid,
                    "n": n,
                    "e": e
                }
            ]
        })
    }

    /// Emit the public key as a PKCS#1 PEM string.
    ///
    /// Used by the legacy JVM 1.x `/jwt/verification-key` compat
    /// endpoint (matrix row E01). PEM is the historical shape
    /// downstream Java consumers of the original TIM expect.
    pub fn public_pem(&self) -> Result<String> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.inner
            .public
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .map(|p| p.to_string())
            .map_err(|e| TimError::Crypto(format!("encode public PKCS#1 PEM: {e}")))
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

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Claims {
        sub: String,
        exp: usize,
        iss: String,
    }

    fn signer() -> JwtSigner {
        JwtSigner::from_pkcs8_pem(TEST_KEY, "test-kid".into()).unwrap()
    }

    #[test]
    fn round_trip_sign_verify() {
        let s = signer();
        let claims = Claims {
            sub: "user-42".into(),
            exp: (chrono::Utc::now().timestamp() + 60) as usize,
            iss: "TIM-TEST".into(),
        };
        let token = s.sign(&claims).unwrap();
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
        let claims = Claims {
            sub: "u".into(),
            exp: 1,
            iss: "TIM-TEST".into(),
        };
        let token = s.sign(&claims).unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.validate_aud = false;
        let err = s.verify::<Claims>(&token, &v).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("verify") || msg.contains("Expired"));
    }
}
