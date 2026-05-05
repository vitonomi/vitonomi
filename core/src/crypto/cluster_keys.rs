//! Cluster-scoped symmetric material derived deterministically from
//! the BIP-39 seed.
//!
//! The `cluster_pepper` and `cluster_shared_key` are HKDF-derived from
//! the seed and live alongside the master secret keys in the
//! AEAD-encrypted key blob. They survive seed-phrase recovery and
//! never traverse the hub in plaintext.
//!
//! See `docs/data-format.md#cluster-pepper--user_lookup_id` and
//! `docs/data-format.md#cluster-shared-key`.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::seedphrase::SeedBytes;
use crate::errors::CryptoError;

/// 32-byte secret used to defeat bulk username enumeration. Stored
/// only inside the encrypted key blob.
#[derive(Clone, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct ClusterPepper(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl ClusterPepper {
    pub const LEN: usize = 32;

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// 32-byte AEAD key used to seal cluster-scoped metadata (vault
/// directory entries, admin chain payloads, etc.).
#[derive(Clone, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct ClusterSharedKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl ClusterSharedKey {
    pub const LEN: usize = 32;

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Wrap as an AEAD key for [`crate::crypto::aead`] usage.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::KeyLength` if internal bytes are not 32.
    pub fn to_aead_key(&self) -> Result<crate::crypto::aead::AeadKey, CryptoError> {
        let arr: [u8; 32] = self
            .0
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::KeyLength {
                expected: 32,
                got: self.0.len(),
            })?;
        Ok(crate::crypto::aead::AeadKey::from_bytes(arr))
    }
}

/// HKDF-SHA-256 info string for `cluster_pepper`.
const PEPPER_INFO: &[u8] = b"vitonomi/cluster_pepper/v1";
/// HKDF-SHA-256 info string for `cluster_shared_key`.
const SHARED_KEY_INFO: &[u8] = b"vitonomi/cluster_shared_key/v1";

/// Derive `cluster_pepper` deterministically from the BIP-39 seed.
#[must_use]
pub fn derive_cluster_pepper(seed: &SeedBytes) -> ClusterPepper {
    let hk = Hkdf::<Sha256>::new(None, seed.as_bytes());
    let mut out = [0u8; ClusterPepper::LEN];
    hk.expand(PEPPER_INFO, &mut out)
        .expect("HKDF expand for cluster_pepper cannot fail at out_len=32");
    ClusterPepper(out.to_vec())
}

/// Derive `cluster_shared_key` deterministically from the BIP-39 seed.
#[must_use]
pub fn derive_cluster_shared_key(seed: &SeedBytes) -> ClusterSharedKey {
    let hk = Hkdf::<Sha256>::new(None, seed.as_bytes());
    let mut out = [0u8; ClusterSharedKey::LEN];
    hk.expand(SHARED_KEY_INFO, &mut out)
        .expect("HKDF expand for cluster_shared_key cannot fail at out_len=32");
    ClusterSharedKey(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::seedphrase::SeedPhrase;

    #[test]
    fn pepper_is_deterministic_from_seed() {
        let phrase = SeedPhrase::generate().unwrap();
        let seed = phrase.to_seed("");
        let p1 = derive_cluster_pepper(&seed);
        let p2 = derive_cluster_pepper(&seed);
        assert_eq!(p1.as_bytes(), p2.as_bytes());
    }

    #[test]
    fn shared_key_is_deterministic_from_seed() {
        let phrase = SeedPhrase::generate().unwrap();
        let seed = phrase.to_seed("");
        let k1 = derive_cluster_shared_key(&seed);
        let k2 = derive_cluster_shared_key(&seed);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn pepper_and_shared_key_are_independent() {
        // Same seed → different outputs (different info strings).
        let phrase = SeedPhrase::generate().unwrap();
        let seed = phrase.to_seed("");
        let pepper = derive_cluster_pepper(&seed);
        let shared = derive_cluster_shared_key(&seed);
        assert_ne!(pepper.as_bytes(), shared.as_bytes());
    }

    #[test]
    fn different_seeds_give_different_material() {
        let p1 = SeedPhrase::generate().unwrap();
        let p2 = SeedPhrase::generate().unwrap();
        let s1 = p1.to_seed("");
        let s2 = p2.to_seed("");
        assert_ne!(
            derive_cluster_pepper(&s1).as_bytes(),
            derive_cluster_pepper(&s2).as_bytes(),
        );
    }
}
