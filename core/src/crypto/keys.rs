//! Master-key bundle held by a cluster creator.
//!
//! In the **production** flow, a user's three master keypairs
//! (`identity`, `cluster_admin`, `kem`) are generated at registration,
//! AEAD-encrypted into a [`crate::crypto::keyblob`], and stored on
//! the hub + IndexedDB + the seed-phrase backup file. Recovery
//! decrypts the blob (via the password-derived encryption key) to get
//! the keys back.
//!
//! Deterministic seed → keypair derivation (which would let the user
//! regenerate the keys from the seed phrase alone, no key blob
//! needed) requires the FIPS 204 / FIPS 203 internal-seed APIs which
//! are not yet exposed by stable Rust PQ crates. When `ml-dsa`
//! stabilises post-rc, we'll add a deterministic-derivation path; in
//! the meantime the multi-tier key-blob storage covers the recovery
//! story.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::cluster_keys::{
    derive_cluster_pepper, derive_cluster_shared_key, ClusterPepper, ClusterSharedKey,
};
use crate::crypto::pq::{
    ml_dsa_65_keypair, ml_kem_768_keypair, MlDsa65Keypair, MlDsa65PublicKey, MlDsa65SecretKey,
    MlKem768Keypair, MlKem768PublicKey, MlKem768SecretKey,
};
use crate::crypto::seedphrase::SeedPhrase;
use crate::record::user_keys::{derive_user_aead_master, UserAeadMaster};

/// All master keys belonging to a cluster creator.
pub struct MasterKeys {
    pub identity: MlDsa65Keypair,
    pub cluster_admin: MlDsa65Keypair,
    pub kem: MlKem768Keypair,
}

impl MasterKeys {
    /// Generate a fresh bundle.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Random` on RNG failure.
    pub fn generate() -> Result<Self, crate::errors::CryptoError> {
        Ok(Self {
            identity: ml_dsa_65_keypair()?,
            cluster_admin: ml_dsa_65_keypair()?,
            kem: ml_kem_768_keypair()?,
        })
    }
}

/// Everything needed to bootstrap a brand-new cluster: random
/// master keypairs PLUS the deterministic-from-seed cluster pepper +
/// cluster shared key + per-user AEAD master. Returned by
/// [`GenesisMaterial::generate`].
pub struct GenesisMaterial {
    pub master_keys: MasterKeys,
    pub seed_phrase: SeedPhrase,
    pub cluster_pepper: ClusterPepper,
    pub cluster_shared_key: ClusterSharedKey,
    pub user_aead_master: UserAeadMaster,
}

impl GenesisMaterial {
    /// Generate a fresh seed phrase + master keys + derived cluster
    /// pepper / shared key / user AEAD master.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Random` if the platform RNG fails.
    pub fn generate() -> Result<Self, crate::errors::CryptoError> {
        let seed_phrase = SeedPhrase::generate()?;
        let seed = seed_phrase.to_seed("");
        Ok(Self {
            master_keys: MasterKeys::generate()?,
            cluster_pepper: derive_cluster_pepper(&seed),
            cluster_shared_key: derive_cluster_shared_key(&seed),
            user_aead_master: derive_user_aead_master(&seed),
            seed_phrase,
        })
    }
}

/// The public-key half of a [`MasterKeys`] bundle. Safe to publish
/// (this is what the hub stores in the user record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MasterPublicKeys {
    pub identity: MlDsa65PublicKey,
    pub cluster_admin: MlDsa65PublicKey,
    pub kem: MlKem768PublicKey,
}

impl From<&MasterKeys> for MasterPublicKeys {
    fn from(k: &MasterKeys) -> Self {
        Self {
            identity: k.identity.public.clone(),
            cluster_admin: k.cluster_admin.public.clone(),
            kem: k.kem.public.clone(),
        }
    }
}

/// The secret-key half of a [`MasterKeys`] bundle PLUS the
/// cluster-scoped symmetric material PLUS the per-user AEAD master
/// (V2). Encrypted into the key blob; never travels in cleartext
/// after first generation.
///
/// Format-version note: this struct's CBOR shape is part of the V2
/// key-blob payload. Adding fields (or reordering) is a key-blob
/// format break. Pre-live, breaking changes are fine — production
/// will rotate everything on the V1 → V2 migration anyway.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MasterSecretKeys {
    /// ML-DSA-65 identity secret-key bytes (32-byte FIPS 204 seed).
    pub identity: MlDsa65SecretKeyBytes,
    /// ML-DSA-65 cluster-admin secret-key bytes.
    pub cluster_admin: MlDsa65SecretKeyBytes,
    /// ML-KEM-768 KEM secret-key bytes (64-byte FIPS 203 seed).
    pub kem: MlKem768SecretKeyBytes,
    /// Cluster pepper (HKDF from BIP-39 seed; defeats `lookup_id`
    /// rainbow-table attacks).
    pub cluster_pepper: ClusterPepper,
    /// Cluster shared AEAD key (HKDF from BIP-39 seed; seals chain
    /// payloads + vault directory entries).
    pub cluster_shared_key: ClusterSharedKey,
    /// Per-user AEAD master (HKDF from BIP-39 seed; IKM for
    /// per-(user, record_type) record-payload + head-pointer keys.
    /// V2 addition — `cluster_shared_key` is derivable by every
    /// cluster member so it can't be the IKM for per-user keys.
    pub user_aead_master: UserAeadMaster,
}

impl MasterSecretKeys {
    /// Build the secret bundle from a freshly generated [`GenesisMaterial`].
    #[must_use]
    pub fn from_genesis(g: &GenesisMaterial) -> Self {
        Self {
            identity: MlDsa65SecretKeyBytes(g.master_keys.identity.secret.0.clone()),
            cluster_admin: MlDsa65SecretKeyBytes(g.master_keys.cluster_admin.secret.0.clone()),
            kem: MlKem768SecretKeyBytes(g.master_keys.kem.secret.0.clone()),
            cluster_pepper: g.cluster_pepper.clone(),
            cluster_shared_key: g.cluster_shared_key.clone(),
            user_aead_master: g.user_aead_master.clone(),
        }
    }

    /// Legacy builder kept for tests + transitional callers; constructs
    /// the secret bundle from random master keys and freshly random
    /// pepper + shared key (NOT seed-derived). Use
    /// [`Self::from_genesis`] in production code.
    #[must_use]
    pub fn from_keypair(k: &MasterKeys) -> Self {
        // For backwards compat with existing tests; production paths
        // should always go through `GenesisMaterial`.
        Self {
            identity: MlDsa65SecretKeyBytes(k.identity.secret.0.clone()),
            cluster_admin: MlDsa65SecretKeyBytes(k.cluster_admin.secret.0.clone()),
            kem: MlKem768SecretKeyBytes(k.kem.secret.0.clone()),
            cluster_pepper: ClusterPepper(vec![0u8; ClusterPepper::LEN]),
            cluster_shared_key: ClusterSharedKey(vec![0u8; ClusterSharedKey::LEN]),
            user_aead_master: UserAeadMaster(vec![0u8; UserAeadMaster::LEN]),
        }
    }
}

/// Serializable wrapper that zeroises on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MlDsa65SecretKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl MlDsa65SecretKeyBytes {
    #[must_use]
    pub fn into_secret_key(self) -> MlDsa65SecretKey {
        MlDsa65SecretKey(self.0.clone())
    }
}

/// Serializable wrapper that zeroises on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MlKem768SecretKeyBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl MlKem768SecretKeyBytes {
    #[must_use]
    pub fn into_secret_key(self) -> MlKem768SecretKey {
        MlKem768SecretKey(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::{ml_dsa_65_sign, ml_dsa_65_verify};

    #[test]
    fn generate_and_use_identity_key() {
        let mk = MasterKeys::generate().unwrap();
        let sig = ml_dsa_65_sign(&mk.identity.secret, b"hello").unwrap();
        ml_dsa_65_verify(&mk.identity.public, &sig, b"hello").unwrap();
    }

    #[test]
    fn admin_and_identity_keys_are_distinct() {
        let mk = MasterKeys::generate().unwrap();
        // Astronomically unlikely the two random keypairs collide.
        assert_ne!(
            mk.identity.public.as_bytes(),
            mk.cluster_admin.public.as_bytes()
        );

        // A signature by identity must NOT verify under cluster-admin pubkey.
        let sig = ml_dsa_65_sign(&mk.identity.secret, b"hello").unwrap();
        assert!(ml_dsa_65_verify(&mk.cluster_admin.public, &sig, b"hello").is_err());
    }

    #[test]
    fn public_keys_round_trip_via_serde() {
        let mk = MasterKeys::generate().unwrap();
        let pubs = MasterPublicKeys::from(&mk);
        let bytes = crate::encoding::cbor_to_vec(&pubs).unwrap();
        let back: MasterPublicKeys = crate::encoding::cbor_from_slice(&bytes).unwrap();
        assert_eq!(back, pubs);
    }

    #[test]
    fn secret_keys_round_trip_via_serde() {
        let mk = MasterKeys::generate().unwrap();
        let secs = MasterSecretKeys::from_keypair(&mk);
        let bytes = crate::encoding::cbor_to_vec(&secs).unwrap();
        let back: MasterSecretKeys = crate::encoding::cbor_from_slice(&bytes).unwrap();
        assert_eq!(back.identity.0, secs.identity.0);
        assert_eq!(back.cluster_admin.0, secs.cluster_admin.0);
        assert_eq!(back.kem.0, secs.kem.0);
    }
}
