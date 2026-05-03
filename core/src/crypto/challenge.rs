//! Challenge / signed-response primitive used for both user login
//! (Scheme A) and vault session handshake.
//!
//! The hub generates a 32-byte random nonce + a server timestamp,
//! sends it to the client / vault, then verifies the returned
//! signature against the stored public key. The signed payload is
//! `nonce || sent_at_be8`.

use serde::{Deserialize, Serialize};

use crate::crypto::pq::{
    ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
};
use crate::crypto::random::random_32;
use crate::errors::CryptoError;

/// Server-issued challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Server-side timestamp at issue (UNIX millis). Bound to the
    /// signature so a replayed nonce after expiry is detectable as
    /// long as expiry is enforced server-side.
    pub sent_at_ms: u64,
}

impl Challenge {
    /// Generate a fresh challenge.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Random` on RNG failure.
    pub fn generate(sent_at_ms: u64) -> Result<Self, CryptoError> {
        let nonce = random_32()?.to_vec();
        Ok(Self { nonce, sent_at_ms })
    }

    /// Bytes fed into the signature.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.nonce.len() + 8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.sent_at_ms.to_be_bytes());
        out
    }
}

/// Signature over the [`Challenge::signed_bytes`].
///
/// # Errors
///
/// Returns `CryptoError::Signature` on signing failure.
pub fn sign_challenge(
    sk: &MlDsa65SecretKey,
    challenge: &Challenge,
) -> Result<MlDsa65Signature, CryptoError> {
    ml_dsa_65_sign(sk, &challenge.signed_bytes())
}

/// Verify a signature over a challenge against the holder's public
/// key.
///
/// # Errors
///
/// Returns `CryptoError::SignatureInvalid` on verification failure.
pub fn verify_challenge(
    pk: &MlDsa65PublicKey,
    challenge: &Challenge,
    sig: &MlDsa65Signature,
) -> Result<(), CryptoError> {
    ml_dsa_65_verify(pk, sig, &challenge.signed_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_dsa_65_keypair;

    #[test]
    fn round_trip() {
        let kp = ml_dsa_65_keypair().unwrap();
        let c = Challenge::generate(1_700_000_000_000).unwrap();
        let sig = sign_challenge(&kp.secret, &c).unwrap();
        verify_challenge(&kp.public, &c, &sig).unwrap();
    }

    #[test]
    fn tampered_nonce_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let c = Challenge::generate(1_700_000_000_000).unwrap();
        let sig = sign_challenge(&kp.secret, &c).unwrap();
        let mut tampered = c.clone();
        tampered.nonce[0] ^= 0x01;
        assert!(verify_challenge(&kp.public, &tampered, &sig).is_err());
    }

    #[test]
    fn tampered_timestamp_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let c = Challenge::generate(1_700_000_000_000).unwrap();
        let sig = sign_challenge(&kp.secret, &c).unwrap();
        let mut tampered = c.clone();
        tampered.sent_at_ms = 0;
        assert!(verify_challenge(&kp.public, &tampered, &sig).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let kp1 = ml_dsa_65_keypair().unwrap();
        let kp2 = ml_dsa_65_keypair().unwrap();
        let c = Challenge::generate(1_700_000_000_000).unwrap();
        let sig = sign_challenge(&kp1.secret, &c).unwrap();
        assert!(verify_challenge(&kp2.public, &c, &sig).is_err());
    }
}
