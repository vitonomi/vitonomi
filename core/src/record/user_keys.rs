//! Per-user AEAD key derivations for the record snapshot chain and
//! the head pointer.
//!
//! The IKM for both is `user_aead_master`: a 32-byte secret stored
//! inside the user's AEAD-encrypted key blob (V2). The IKM is
//! HKDF-derived from the BIP-39 seed at registration with info
//! `"vitonomi/user_aead_master/v1"`; recovery from seed regenerates
//! the same `user_aead_master` deterministically.
//!
//! Why not `cluster_shared_key` as IKM: every cluster member can
//! derive `cluster_shared_key` (it's the K2 path). Using it as IKM
//! would let any cluster member derive any other member's per-user
//! record AEAD key. `user_aead_master` lives only in the user's own
//! key blob, never in the cluster shared key, so per-user records
//! stay opaque across cluster members.
//!
//! Salt isolates per-user material; info string isolates the
//! record-type sub-key from the head-pointer sub-key.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::aead::AeadKey;
use crate::errors::CryptoError;
use crate::record::RecordType;
use crate::types::UserId;

/// HKDF-SHA-256 info prefix for the per-(user, record_type) AEAD
/// key. Concatenated with the record-type discriminator byte.
const RECORD_AEAD_INFO_PREFIX: &[u8] = b"vitonomi/record_aead/v1/";

/// HKDF-SHA-256 info string for the per-user head-pointer AEAD key.
const HEAD_POINTER_AEAD_INFO: &[u8] = b"vitonomi/head_pointer_aead/v1";

/// 32-byte master from which `user_record_aead` and
/// `user_head_pointer_aead` keys are derived. Stored only inside the
/// user's AEAD-encrypted key blob (V2 format).
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct UserAeadMaster(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl UserAeadMaster {
    pub const LEN: usize = 32;

    /// Allocate from existing bytes (length-checked).
    ///
    /// # Errors
    ///
    /// `CryptoError::KeyLength` if `bytes.len() != 32`.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.len() != Self::LEN {
            return Err(CryptoError::KeyLength {
                expected: Self::LEN,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Derive [`UserAeadMaster`] deterministically from the BIP-39 seed.
/// Mirrors the `cluster_pepper` / `cluster_shared_key` derivation
/// pattern in `crypto::cluster_keys`.
#[must_use]
pub fn derive_user_aead_master(seed: &crate::crypto::seedphrase::SeedBytes) -> UserAeadMaster {
    let hk = Hkdf::<Sha256>::new(None, seed.as_bytes());
    let mut out = [0u8; UserAeadMaster::LEN];
    hk.expand(b"vitonomi/user_aead_master/v1", &mut out)
        .expect("HKDF expand for user_aead_master cannot fail at out_len=32");
    UserAeadMaster(out.to_vec())
}

/// Derive the per-(user, record_type) AEAD key used to seal record
/// payloads + signed snapshot envelopes.
///
/// `IKM = user_aead_master`, `salt = user_id (16 bytes)`,
/// `info = b"vitonomi/record_aead/v1/" || [record_type_byte]`.
///
/// # Errors
///
/// `CryptoError::Kdf` if HKDF expansion fails (unreachable at
/// `out_len = 32`).
pub fn derive_record_aead_key(
    master: &UserAeadMaster,
    user_id: UserId,
    record_type: RecordType,
) -> Result<AeadKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(&user_id.0), master.as_bytes());
    let mut info = Vec::with_capacity(RECORD_AEAD_INFO_PREFIX.len() + 1);
    info.extend_from_slice(RECORD_AEAD_INFO_PREFIX);
    info.push(record_type.as_u8());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|e| CryptoError::Kdf(format!("record AEAD key: {e}")))?;
    Ok(AeadKey::from_bytes(out))
}

/// Derive the per-user head-pointer AEAD key.
///
/// `IKM = user_aead_master`, `salt = user_id (16 bytes)`,
/// `info = "vitonomi/head_pointer_aead/v1"`.
///
/// # Errors
///
/// `CryptoError::Kdf` on HKDF expansion failure (unreachable).
pub fn derive_head_pointer_aead_key(
    master: &UserAeadMaster,
    user_id: UserId,
) -> Result<AeadKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(&user_id.0), master.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(HEAD_POINTER_AEAD_INFO, &mut out)
        .map_err(|e| CryptoError::Kdf(format!("head pointer AEAD key: {e}")))?;
    Ok(AeadKey::from_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::seedphrase::SeedPhrase;

    fn user(byte: u8) -> UserId {
        UserId([byte; 16])
    }

    #[test]
    fn user_aead_master_deterministic_from_seed() {
        let phrase = SeedPhrase::generate().unwrap();
        let seed = phrase.to_seed("");
        let a = derive_user_aead_master(&seed);
        let b = derive_user_aead_master(&seed);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn user_aead_master_differs_across_seeds() {
        let p1 = SeedPhrase::generate().unwrap();
        let p2 = SeedPhrase::generate().unwrap();
        assert_ne!(
            derive_user_aead_master(&p1.to_seed("")).as_bytes(),
            derive_user_aead_master(&p2.to_seed("")).as_bytes(),
        );
    }

    #[test]
    fn user_aead_master_independent_of_cluster_keys() {
        // The pepper, shared_key, and user_aead_master share an IKM
        // but use distinct HKDF info strings, so their outputs are
        // independent.
        let phrase = SeedPhrase::generate().unwrap();
        let seed = phrase.to_seed("");
        let user_master = derive_user_aead_master(&seed);
        let cluster_pepper = crate::crypto::cluster_keys::derive_cluster_pepper(&seed);
        let cluster_shared = crate::crypto::cluster_keys::derive_cluster_shared_key(&seed);
        assert_ne!(user_master.as_bytes(), cluster_pepper.as_bytes());
        assert_ne!(user_master.as_bytes(), cluster_shared.as_bytes());
        assert_ne!(cluster_pepper.as_bytes(), cluster_shared.as_bytes());
    }

    #[test]
    fn record_aead_keys_isolate_per_user() {
        let phrase = SeedPhrase::generate().unwrap();
        let master = derive_user_aead_master(&phrase.to_seed(""));
        let k1 = derive_record_aead_key(&master, user(1), RecordType::Credential).unwrap();
        let k2 = derive_record_aead_key(&master, user(2), RecordType::Credential).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn record_aead_keys_isolate_per_record_type() {
        let phrase = SeedPhrase::generate().unwrap();
        let master = derive_user_aead_master(&phrase.to_seed(""));
        let k_cred = derive_record_aead_key(&master, user(1), RecordType::Credential).unwrap();
        let k_alias = derive_record_aead_key(&master, user(1), RecordType::Alias).unwrap();
        assert_ne!(k_cred.as_bytes(), k_alias.as_bytes());
    }

    #[test]
    fn head_pointer_key_distinct_from_record_keys() {
        let phrase = SeedPhrase::generate().unwrap();
        let master = derive_user_aead_master(&phrase.to_seed(""));
        let head = derive_head_pointer_aead_key(&master, user(1)).unwrap();
        let cred = derive_record_aead_key(&master, user(1), RecordType::Credential).unwrap();
        assert_ne!(head.as_bytes(), cred.as_bytes());
    }

    #[test]
    fn derived_keys_deterministic_from_master() {
        let phrase = SeedPhrase::generate().unwrap();
        let master = derive_user_aead_master(&phrase.to_seed(""));
        let k1 = derive_record_aead_key(&master, user(1), RecordType::Credential).unwrap();
        let k2 = derive_record_aead_key(&master, user(1), RecordType::Credential).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }
}
