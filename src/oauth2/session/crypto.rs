//! AEAD envelope for at-rest session tokens.
//!
//! The `PostgresStore` persists an encrypted blob per row rather than
//! plaintext profile data — profile claims copied from IdP ID tokens
//! may carry PII and MUST NOT sit unencrypted on disk.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use crate::error::{Result, TimError};

const NONCE_LEN: usize = 12;

#[derive(Clone)]
pub struct SessionCipher {
    inner: ChaCha20Poly1305,
}

impl SessionCipher {
    /// Accepts a hex-encoded 32-byte key (64 hex chars). Panics-safe:
    /// returns TimError::Config on any parse failure.
    pub fn from_hex_key(hex_key: &str) -> Result<Self> {
        let bytes = hex::decode(hex_key.trim())
            .map_err(|e| TimError::Config(format!("session key hex decode: {e}")))?;
        if bytes.len() != 32 {
            return Err(TimError::Config(format!(
                "session key must be 32 bytes (64 hex chars); got {}",
                bytes.len()
            )));
        }
        let key = Key::from_slice(&bytes);
        Ok(Self {
            inner: ChaCha20Poly1305::new(key),
        })
    }

    /// Output layout: `[nonce (12 bytes)][ciphertext + tag]`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .inner
            .encrypt(nonce, plaintext)
            .map_err(|e| TimError::Crypto(format!("session AEAD encrypt: {e}")))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            return Err(TimError::Crypto("session AEAD blob too short".into()));
        }
        let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.inner
            .decrypt(nonce, ct)
            .map_err(|e| TimError::Crypto(format!("session AEAD decrypt: {e}")))
    }
}

// Minimal hex decoder — we already use hex encoding in flow::random_hex.
// Avoids pulling a whole `hex` crate for one function.
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let s = s.trim();
        if !s.len().is_multiple_of(2) {
            return Err("odd length".into());
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for chunk in s.as_bytes().chunks(2) {
            let hi = from_hex_digit(chunk[0])?;
            let lo = from_hex_digit(chunk[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }
    fn from_hex_digit(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            other => Err(format!("non-hex character: {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        "a".repeat(64)
    }

    #[test]
    fn round_trip_roundtrips() {
        let c = SessionCipher::from_hex_key(&key()).unwrap();
        let pt = b"hello world";
        let sealed = c.seal(pt).unwrap();
        assert_ne!(&sealed[..], pt);
        let out = c.open(&sealed).unwrap();
        assert_eq!(&out, pt);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let a = SessionCipher::from_hex_key(&key()).unwrap();
        let b = SessionCipher::from_hex_key(&"b".repeat(64)).unwrap();
        let sealed = a.seal(b"secret").unwrap();
        assert!(b.open(&sealed).is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let c = SessionCipher::from_hex_key(&key()).unwrap();
        let mut sealed = c.seal(b"abc").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(c.open(&sealed).is_err());
    }

    #[test]
    fn rejects_short_key() {
        assert!(SessionCipher::from_hex_key("abc").is_err());
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(SessionCipher::from_hex_key(&"z".repeat(64)).is_err());
    }
}
