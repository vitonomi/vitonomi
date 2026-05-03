//! XChaCha20-Poly1305 AEAD. 256-bit key, 192-bit (24-byte) nonce so a
//! random per-message nonce is collision-safe.
//!
//! Convention: callers MUST supply unique nonces; helpers below
//! generate fresh nonces from the platform RNG. Associated data is
//! authenticated but not encrypted; pass the same `aad` on seal and
//! open.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::random::random_bytes;
use crate::errors::CryptoError;

/// 256-bit AEAD key. Zeroised on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; 32]);

impl AeadKey {
    /// Wrap a 32-byte key.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh key from the platform RNG.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Random` if the platform RNG fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes = random_bytes(32)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::KeyLength {
                expected: 32,
                got: bytes.len(),
            })?;
        Ok(Self(arr))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 24-byte XChaCha20 nonce. Random per message.
pub const NONCE_LEN: usize = 24;
/// AEAD authentication tag length.
pub const TAG_LEN: usize = 16;

/// Encrypted blob: `nonce || ciphertext || tag`. The nonce is in the
/// header so it travels with the ciphertext.
pub struct AeadCiphertext(pub Vec<u8>);

/// Seal `plaintext` under `key` with associated data `aad`. The
/// returned bytes are `nonce || ciphertext || tag`.
///
/// # Errors
///
/// Returns `CryptoError::AeadSeal` on encryption failure (effectively
/// only happens if the nonce-generation RNG fails).
pub fn seal(key: &AeadKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce_bytes = random_bytes(NONCE_LEN)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadSeal)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a `nonce || ciphertext || tag` blob produced by [`seal`].
///
/// # Errors
///
/// Returns `CryptoError::AeadOpen` on tampered, truncated, or
/// wrong-key input.
pub fn open(key: &AeadKey, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::AeadOpen);
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| CryptoError::AeadOpen)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> AeadKey {
        AeadKey::from_bytes([7u8; 32])
    }

    #[test]
    fn round_trip() {
        let key = fixed_key();
        let pt = b"hello vitonomi";
        let aad = b"context-tag";
        let ct = seal(&key, pt, aad).unwrap();
        assert_ne!(
            ct[NONCE_LEN..],
            pt[..],
            "ciphertext should differ from plaintext"
        );
        let out = open(&key, &ct, aad).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = fixed_key();
        let ct = seal(&key, b"", b"").unwrap();
        let out = open(&key, &ct, b"").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn wrong_key_rejected() {
        let key1 = AeadKey::from_bytes([1u8; 32]);
        let key2 = AeadKey::from_bytes([2u8; 32]);
        let ct = seal(&key1, b"secret", b"ad").unwrap();
        assert!(matches!(
            open(&key2, &ct, b"ad"),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn wrong_aad_rejected() {
        let key = fixed_key();
        let ct = seal(&key, b"secret", b"ad-1").unwrap();
        assert!(matches!(
            open(&key, &ct, b"ad-2"),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = fixed_key();
        let mut ct = seal(&key, b"secret", b"ad").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(open(&key, &ct, b"ad"), Err(CryptoError::AeadOpen)));
    }

    #[test]
    fn tampered_nonce_rejected() {
        let key = fixed_key();
        let mut ct = seal(&key, b"secret", b"ad").unwrap();
        ct[0] ^= 0x01;
        assert!(matches!(open(&key, &ct, b"ad"), Err(CryptoError::AeadOpen)));
    }

    #[test]
    fn truncated_ciphertext_rejected() {
        let key = fixed_key();
        let ct = seal(&key, b"secret", b"ad").unwrap();
        // Drop tag bytes.
        let trunc = &ct[..ct.len() - TAG_LEN];
        assert!(matches!(
            open(&key, trunc, b"ad"),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn nonces_differ_between_calls() {
        let key = fixed_key();
        let pt = b"same plaintext";
        let aad = b"same aad";
        let a = seal(&key, pt, aad).unwrap();
        let b = seal(&key, pt, aad).unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN], "nonces should differ");
    }
}
