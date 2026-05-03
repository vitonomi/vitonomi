//! Cluster identifier + invite-token signing.
//!
//! `cluster_id = sha256(cluster_admin_pubkey_bytes || format_version_byte)`.
//! Stable across hubs because it's seed-derivable from the user's
//! cluster admin keypair.
//!
//! The invite token is an admin-signed CBOR envelope authorising a
//! single vault to join the cluster.

use sha2::{Digest, Sha256};

use crate::crypto::pq::{
    ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
};
use crate::errors::CryptoError;
use crate::types::{ClusterId, FormatVersion};

/// Compute the cluster id from the cluster admin's ML-DSA-65 public
/// key and a format version.
#[must_use]
pub fn cluster_id_of(admin_pubkey: &MlDsa65PublicKey, version: FormatVersion) -> ClusterId {
    let mut h = Sha256::new();
    h.update(admin_pubkey.as_bytes());
    h.update([version.as_u8()]);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    ClusterId(out)
}

/// Sign an arbitrary invite payload with the cluster admin secret
/// key. Higher layers wrap the bytes returned here in a
/// [`crate::protocol::wire::accept::InviteToken`].
///
/// # Errors
///
/// Returns `CryptoError::Signature` on signing failure.
pub fn sign_invite_payload(
    admin_sk: &MlDsa65SecretKey,
    payload_bytes: &[u8],
) -> Result<MlDsa65Signature, CryptoError> {
    ml_dsa_65_sign(admin_sk, payload_bytes)
}

/// Verify an invite payload signature against the cluster admin
/// public key.
///
/// # Errors
///
/// Returns `CryptoError::SignatureInvalid` on bad signature.
pub fn verify_invite_payload(
    admin_pk: &MlDsa65PublicKey,
    payload_bytes: &[u8],
    sig: &MlDsa65Signature,
) -> Result<(), CryptoError> {
    ml_dsa_65_verify(admin_pk, sig, payload_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_dsa_65_keypair;

    #[test]
    fn cluster_id_is_deterministic() {
        let kp = ml_dsa_65_keypair().unwrap();
        let id1 = cluster_id_of(&kp.public, FormatVersion::V1);
        let id2 = cluster_id_of(&kp.public, FormatVersion::V1);
        assert_eq!(id1, id2);
    }

    #[test]
    fn cluster_id_differs_per_pubkey() {
        let a = ml_dsa_65_keypair().unwrap();
        let b = ml_dsa_65_keypair().unwrap();
        assert_ne!(
            cluster_id_of(&a.public, FormatVersion::V1),
            cluster_id_of(&b.public, FormatVersion::V1),
        );
    }

    #[test]
    fn cluster_id_changes_with_version() {
        let kp = ml_dsa_65_keypair().unwrap();
        let v1 = cluster_id_of(&kp.public, FormatVersion(1));
        let v2 = cluster_id_of(&kp.public, FormatVersion(2));
        assert_ne!(v1, v2);
    }

    #[test]
    fn invite_round_trip() {
        let kp = ml_dsa_65_keypair().unwrap();
        let payload = b"cluster=42, vault_role=storage, expires=...";
        let sig = sign_invite_payload(&kp.secret, payload).unwrap();
        verify_invite_payload(&kp.public, payload, &sig).unwrap();
    }

    #[test]
    fn invite_tamper_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let sig = sign_invite_payload(&kp.secret, b"original").unwrap();
        assert!(verify_invite_payload(&kp.public, b"tampered", &sig).is_err());
    }
}
