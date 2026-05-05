//! Per-invite key-encrypting-key (KEK) used to seal `cluster_shared_key`
//! inside the invite token's inner payload (K2 delivery).
//!
//! The admin computes
//! `invite_kek = HKDF-SHA-256(cluster_admin_sk_bytes,
//!   info="vitonomi/invite_kek/v1", salt=invite_nonce, out_len=32)`.
//! Only the admin can produce this (the cluster admin sk never leaves
//! the admin's device); the vault receives the inner payload AND the
//! KEK out-of-band (typically via the invite-token string the operator
//! pastes), then unseals `cluster_shared_key`.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::aead::AeadKey;
use crate::crypto::pq::MlDsa65SecretKey;
use crate::errors::CryptoError;

/// HKDF info string for invite-KEK derivation.
const INFO: &[u8] = b"vitonomi/invite_kek/v1";

/// 32-byte invite-scoped KEK. Zeroised on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InviteKek(pub Vec<u8>);

impl InviteKek {
    /// Derive the KEK from the cluster admin sk bytes and the
    /// `invite_nonce`.
    ///
    /// # Errors
    ///
    /// Currently infallible at out_len=32.
    pub fn derive(
        cluster_admin_sk: &MlDsa65SecretKey,
        invite_nonce: &[u8],
    ) -> Result<Self, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(invite_nonce), cluster_admin_sk.as_bytes());
        let mut out = [0u8; 32];
        hk.expand(INFO, &mut out)
            .expect("HKDF expand for invite_kek cannot fail at out_len=32");
        Ok(Self(out.to_vec()))
    }

    /// Wrap as an [`AeadKey`] for sealing/unsealing the inner payload.
    #[must_use]
    pub fn to_aead_key(&self) -> AeadKey {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.0);
        AeadKey::from_bytes(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_dsa_65_keypair;

    #[test]
    fn deterministic_for_same_inputs() {
        let kp = ml_dsa_65_keypair().unwrap();
        let nonce = vec![0xaa; 32];
        let k1 = InviteKek::derive(&kp.secret, &nonce).unwrap();
        let k2 = InviteKek::derive(&kp.secret, &nonce).unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn different_nonces_diverge() {
        let kp = ml_dsa_65_keypair().unwrap();
        let n1 = vec![1u8; 32];
        let n2 = vec![2u8; 32];
        assert_ne!(
            InviteKek::derive(&kp.secret, &n1).unwrap().0,
            InviteKek::derive(&kp.secret, &n2).unwrap().0,
        );
    }

    #[test]
    fn different_admins_diverge() {
        let kp1 = ml_dsa_65_keypair().unwrap();
        let kp2 = ml_dsa_65_keypair().unwrap();
        let nonce = vec![0u8; 32];
        assert_ne!(
            InviteKek::derive(&kp1.secret, &nonce).unwrap().0,
            InviteKek::derive(&kp2.secret, &nonce).unwrap().0,
        );
    }
}
