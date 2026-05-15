//! KEM-then-AEAD primitive for inbound alias mail.
//!
//! Inbound mail received by `vitonomi-mx` is sealed in RAM
//! against the alias's published [`MlKem768PublicKey`] and
//! pushed to the user's hub as ciphertext. The user fetches
//! the envelope from the per-alias inbound queue and decrypts
//! locally with the alias's [`MlKem768SecretKey`].
//!
//! # Pipeline
//!
//! 1. `ml_kem_768_encaps(pk)` → `(shared_secret, kem_ciphertext)`
//! 2. `aead_key = HKDF-SHA-256(salt = none, ikm = shared_secret,
//!    info = b"vitonomi/alias_inbound/aead/v1")` → 32 B
//! 3. Generate 24-byte XChaCha20 nonce from
//!    [`crate::crypto::random::fill_random`]
//! 4. XChaCha20-Poly1305 seal under `aead_key`, the fresh
//!    nonce, the binding AAD, and the plaintext
//! 5. The KEM shared secret zeroizes on drop
//!
//! # AAD recipe
//!
//! ```text
//! b"vitonomi/alias_inbound/v1" || alias_id(16) || received_at_ms(8 le)
//! ```
//!
//! - `alias_id` binding prevents cross-alias substitution: a
//!   relay-adjacent attacker can't replay one alias's envelope
//!   to a different alias slot.
//! - `received_at_ms` binding prevents the relay from
//!   re-stating an old envelope under a new server timestamp at
//!   the hub-push step. The user's client passes both values
//!   into [`open_from_alias`]; mismatch fails AEAD-open.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::pq::{
    ml_kem_768_decaps, ml_kem_768_encaps, MlKem768Ciphertext, MlKem768PublicKey, MlKem768SecretKey,
};
use crate::crypto::random::fill_random;
use crate::errors::CryptoError;
use crate::record::RecordId;
use crate::types::FormatVersion;

/// XChaCha20 nonce length (24 bytes).
pub const NONCE_LEN: usize = 24;

/// Sealed inbound mail. Wire layout pinned in
/// `docs/data-format.md` §"Alias inbound envelope".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasInboundCiphertext {
    pub format_version: FormatVersion,
    pub kem_ciphertext: MlKem768Ciphertext,
    /// Fixed-length 24-byte XChaCha20 nonce.
    #[serde(with = "serde_bytes")]
    pub aead_nonce: Vec<u8>,
    /// XChaCha20-Poly1305 ciphertext (`plaintext.len() + 16`).
    #[serde(with = "serde_bytes")]
    pub aead_payload: Vec<u8>,
}

/// Build the AAD bytes the AEAD seals under.
///
/// ```text
/// b"vitonomi/alias_inbound/v1" || alias_id(16) || received_at_ms(8 le)
/// ```
#[must_use]
pub fn alias_inbound_aad(alias_id: RecordId, received_at_ms: u64) -> Vec<u8> {
    let prefix: &[u8] = b"vitonomi/alias_inbound/v1";
    let mut out = Vec::with_capacity(prefix.len() + 16 + 8);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&alias_id.0);
    out.extend_from_slice(&received_at_ms.to_le_bytes());
    out
}

/// Encapsulate to `pk` and AEAD-seal `plaintext` so only the
/// holder of the matching [`MlKem768SecretKey`] can recover it.
/// Binds `alias_id` + `received_at_ms` into the AAD per
/// [`alias_inbound_aad`].
///
/// # Errors
///
/// `CryptoError::Random` if the platform RNG fails;
/// `CryptoError::Kem` on a malformed `pk`;
/// `CryptoError::AeadSeal` on AEAD failure.
pub fn seal_to_alias(
    pk: &MlKem768PublicKey,
    alias_id: RecordId,
    received_at_ms: u64,
    plaintext: &[u8],
) -> Result<AliasInboundCiphertext, CryptoError> {
    let (shared_secret, kem_ct) = ml_kem_768_encaps(pk)?;
    let aead_key = derive_aead_key(shared_secret.0.as_slice())?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes)?;
    let aad = alias_inbound_aad(alias_id, received_at_ms);
    let cipher = XChaCha20Poly1305::new((&aead_key).into());
    let payload = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadSeal)?;
    Ok(AliasInboundCiphertext {
        format_version: FormatVersion::V1,
        kem_ciphertext: kem_ct,
        aead_nonce: nonce_bytes.to_vec(),
        aead_payload: payload,
    })
}

/// Recover the plaintext from a [`seal_to_alias`] envelope.
/// `alias_id` and `received_at_ms` MUST match the values used
/// when sealing — they're bound into the AAD.
///
/// # Errors
///
/// `CryptoError::Kem` on a malformed `sk` or `kem_ciphertext`;
/// `CryptoError::AeadOpen` on tampered / wrong-key /
/// AAD-mismatch input;
/// `CryptoError::Kdf` on a wrong-length nonce.
pub fn open_from_alias(
    sk: &MlKem768SecretKey,
    alias_id: RecordId,
    received_at_ms: u64,
    ct: &AliasInboundCiphertext,
) -> Result<Vec<u8>, CryptoError> {
    if ct.aead_nonce.len() != NONCE_LEN {
        return Err(CryptoError::Kdf(format!(
            "alias_inbound nonce must be {NONCE_LEN} bytes, got {}",
            ct.aead_nonce.len()
        )));
    }
    let shared_secret = ml_kem_768_decaps(sk, &ct.kem_ciphertext)?;
    let aead_key = derive_aead_key(shared_secret.0.as_slice())?;
    let aad = alias_inbound_aad(alias_id, received_at_ms);
    let cipher = XChaCha20Poly1305::new((&aead_key).into());
    let pt = cipher
        .decrypt(
            XNonce::from_slice(&ct.aead_nonce),
            Payload {
                msg: &ct.aead_payload,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadOpen)?;
    Ok(pt)
}

/// HKDF-SHA-256 derives the AEAD key from the KEM shared
/// secret. Salt is None; info string isolates this derivation
/// from any other use of the same shared secret.
fn derive_aead_key(shared_secret: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; 32];
    hk.expand(b"vitonomi/alias_inbound/aead/v1", &mut out)
        .map_err(|e| CryptoError::Kdf(format!("alias_inbound HKDF expand: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_kem_768_keypair;
    use std::collections::HashSet;

    fn fixture_alias_id() -> RecordId {
        RecordId([0x42; 16])
    }

    fn fresh_envelope(plaintext: &[u8]) -> (AliasInboundCiphertext, MlKem768SecretKey, RecordId, u64) {
        let kp = ml_kem_768_keypair().unwrap();
        let alias_id = fixture_alias_id();
        let now = 1_700_000_000_000u64;
        let ct = seal_to_alias(&kp.public, alias_id, now, plaintext).unwrap();
        (ct, kp.secret, alias_id, now)
    }

    #[test]
    fn round_trip_seal_open() {
        let pt = b"From: alice@example.com\r\n\r\nHello vitonomi!";
        let (ct, sk, id, now) = fresh_envelope(pt);
        let back = open_from_alias(&sk, id, now, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn wrong_secret_key_fails_decap() {
        let (ct, _sk, id, now) = fresh_envelope(b"hello");
        let other = ml_kem_768_keypair().unwrap();
        let res = open_from_alias(&other.secret, id, now, &ct);
        assert!(matches!(res, Err(CryptoError::AeadOpen)));
    }

    #[test]
    fn tampered_aead_payload_fails_open() {
        let (mut ct, sk, id, now) = fresh_envelope(b"hello");
        let last = ct.aead_payload.len() - 1;
        ct.aead_payload[last] ^= 0x01;
        assert!(matches!(
            open_from_alias(&sk, id, now, &ct),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn tampered_kem_ciphertext_fails_open() {
        let (mut ct, sk, id, now) = fresh_envelope(b"hello");
        ct.kem_ciphertext.0[0] ^= 0x01;
        // Decap with a tampered ct yields a *different* shared
        // secret (KEM is implicit-rejection); AEAD-open then
        // fails the tag check.
        assert!(matches!(
            open_from_alias(&sk, id, now, &ct),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn mismatched_alias_id_in_aad_fails_open() {
        let (ct, sk, _id, now) = fresh_envelope(b"hello");
        let other = RecordId([0xee; 16]);
        assert!(matches!(
            open_from_alias(&sk, other, now, &ct),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn mismatched_received_at_ms_in_aad_fails_open() {
        let (ct, sk, id, now) = fresh_envelope(b"hello");
        assert!(matches!(
            open_from_alias(&sk, id, now + 1, &ct),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn wrong_length_nonce_rejected_with_typed_error() {
        let (mut ct, sk, id, now) = fresh_envelope(b"hello");
        ct.aead_nonce.truncate(12); // corrupt: too short
        assert!(matches!(
            open_from_alias(&sk, id, now, &ct),
            Err(CryptoError::Kdf(_))
        ));
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let (ct, sk, id, now) = fresh_envelope(b"");
        let back = open_from_alias(&sk, id, now, &ct).unwrap();
        assert!(back.is_empty());
    }

    #[test]
    fn large_plaintext_round_trip() {
        let pt: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
        let (ct, sk, id, now) = fresh_envelope(&pt);
        let back = open_from_alias(&sk, id, now, &ct).unwrap();
        assert_eq!(back.len(), pt.len());
        assert_eq!(back, pt);
    }

    #[test]
    fn nonce_uniqueness_across_seal_calls() {
        let kp = ml_kem_768_keypair().unwrap();
        let id = fixture_alias_id();
        let now = 1u64;
        let mut nonces = HashSet::new();
        for _ in 0..1000 {
            let ct = seal_to_alias(&kp.public, id, now, b"x").unwrap();
            assert!(
                nonces.insert(ct.aead_nonce.clone()),
                "RNG produced a colliding nonce — XChaCha20 nonce reuse \
                 would be catastrophic for confidentiality"
            );
        }
    }

    #[test]
    fn aad_recipe_is_unique_per_input_combo() {
        let a = alias_inbound_aad(RecordId([1; 16]), 1);
        let b = alias_inbound_aad(RecordId([2; 16]), 1);
        let c = alias_inbound_aad(RecordId([1; 16]), 2);
        assert_ne!(a, b, "alias_id changes the AAD");
        assert_ne!(a, c, "received_at_ms changes the AAD");
    }

    #[test]
    fn ciphertext_round_trips_via_cbor() {
        use crate::encoding::{cbor_from_slice, cbor_to_vec};
        let (ct, _sk, _id, _now) = fresh_envelope(b"some bytes");
        let bytes = cbor_to_vec(&ct).unwrap();
        let back: AliasInboundCiphertext = cbor_from_slice(&bytes).unwrap();
        assert_eq!(back, ct);
    }

    #[test]
    fn ciphertext_layout_field_lengths_are_stable() {
        let (ct, _sk, _id, _now) = fresh_envelope(b"hello");
        // ML-KEM-768 ciphertext is fixed at 1088 bytes.
        assert_eq!(ct.kem_ciphertext.0.len(), 1088);
        // 24-byte XChaCha20 nonce.
        assert_eq!(ct.aead_nonce.len(), 24);
        // AEAD payload = plaintext (5) + 16-byte tag.
        assert_eq!(ct.aead_payload.len(), 5 + 16);
    }
}
