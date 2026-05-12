//! Head pointer envelope: pointer to the latest snapshot for a
//! given (user, record_type).
//!
//! Layered:
//!
//! 1. `HeadPointer` (plaintext, serde-CBOR) — `snapshot_data_map`
//!    travels inline so a fresh client fetches the latest snapshot
//!    in one round trip.
//! 2. AEAD-encrypted under
//!    [`crate::record::user_keys::derive_head_pointer_aead_key`].
//!    AAD: `b"vitonomi/head_pointer/v1" || cluster_id(32) ||
//!    user_id(16) || record_type(1)`.
//! 3. Wrapped into a [`StoredHeadPointer`] which exposes a plaintext
//!    `seq` (for rollback protection at the hub) and a
//!    `sig_user_outer` over
//!    `(cluster_id || user_id || record_type || seq_be8 ||
//!    sha256(encrypted_pointer))`. The outer sig prevents a malicious
//!    hub from substituting a fabricated body.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::aead::{open, seal, AeadKey};
use crate::crypto::pq::{
    ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
};
use crate::crypto::selfencrypt::DataMap;
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::CryptoError;
use crate::record::RecordType;
use crate::types::{ClusterId, FormatVersion, UserId};

/// Plaintext head pointer. AEAD-encrypted before sending to the hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadPointer {
    pub format_version: FormatVersion,
    pub snapshot_data_map: DataMap,
    pub seq: u64,
    /// Inner signature over `(snapshot_data_map.bytes || seq_be8)`.
    /// Lets a client verify the AEAD-decrypted body was authored by
    /// the user identity sk (not just whoever has the AEAD key).
    pub sig_user_inner: MlDsa65Signature,
}

/// What gets persisted on the hub. The hub sees only:
/// - `seq` (plaintext, monotonic — rollback protection key);
/// - `encrypted_pointer` (opaque ciphertext);
/// - `sig_user_outer` (forgery protection across `cluster_id, user_id,
///   record_type, seq, sha256(ct)`).
///
/// Everything else is sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredHeadPointer {
    pub format_version: FormatVersion,
    pub seq: u64,
    #[serde(with = "serde_bytes")]
    pub encrypted_pointer: Vec<u8>,
    pub sig_user_outer: MlDsa65Signature,
}

/// Bytes the outer signature commits to.
///
/// Stable layout: 32 (cluster) + 16 (user) + 1 (record_type) + 8
/// (seq BE) + 32 (sha256 of `encrypted_pointer`).
#[must_use]
pub fn outer_signed_bytes(
    cluster_id: &ClusterId,
    user_id: &UserId,
    record_type: RecordType,
    seq: u64,
    encrypted_pointer: &[u8],
) -> [u8; 32 + 16 + 1 + 8 + 32] {
    let mut buf = [0u8; 32 + 16 + 1 + 8 + 32];
    buf[..32].copy_from_slice(&cluster_id.0);
    buf[32..48].copy_from_slice(&user_id.0);
    buf[48] = record_type.as_u8();
    buf[49..57].copy_from_slice(&seq.to_be_bytes());
    let mut hasher = Sha256::new();
    hasher.update(encrypted_pointer);
    let h = hasher.finalize();
    buf[57..89].copy_from_slice(&h);
    buf
}

/// AAD bound into the AEAD seal.
#[must_use]
pub fn head_pointer_aad(
    cluster_id: &ClusterId,
    user_id: &UserId,
    record_type: RecordType,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(28 + 32 + 16 + 1);
    aad.extend_from_slice(b"vitonomi/head_pointer/v1");
    aad.extend_from_slice(&cluster_id.0);
    aad.extend_from_slice(&user_id.0);
    aad.push(record_type.as_u8());
    aad
}

/// Build the inner-sig bytes: `data_map.bytes || seq_be8`.
fn inner_signed_bytes(snapshot_data_map: &DataMap, seq: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(snapshot_data_map.0.len() + 8);
    out.extend_from_slice(&snapshot_data_map.0);
    out.extend_from_slice(&seq.to_be_bytes());
    out
}

/// Build + seal + outer-sign a head pointer.
///
/// # Errors
///
/// Any crypto / serialisation failure (`CryptoError`).
pub fn seal_head_pointer(
    user_enc_key: &AeadKey,
    identity_sk: &MlDsa65SecretKey,
    cluster_id: &ClusterId,
    user_id: &UserId,
    record_type: RecordType,
    snapshot_data_map: DataMap,
    seq: u64,
) -> Result<StoredHeadPointer, CryptoError> {
    // Inner sig commits the user to the DataMap + seq pairing.
    let sig_user_inner = ml_dsa_65_sign(identity_sk, &inner_signed_bytes(&snapshot_data_map, seq))?;
    let pointer = HeadPointer {
        format_version: FormatVersion::V1,
        snapshot_data_map,
        seq,
        sig_user_inner,
    };
    let pt =
        cbor_to_vec(&pointer).map_err(|e| CryptoError::Kdf(format!("head pointer CBOR: {e}")))?;
    let aad = head_pointer_aad(cluster_id, user_id, record_type);
    let encrypted_pointer = seal(user_enc_key, &pt, &aad)?;

    // Outer sig commits user_id + record_type + seq + ct hash.
    let outer = outer_signed_bytes(cluster_id, user_id, record_type, seq, &encrypted_pointer);
    let sig_user_outer = ml_dsa_65_sign(identity_sk, &outer)?;

    Ok(StoredHeadPointer {
        format_version: FormatVersion::V1,
        seq,
        encrypted_pointer,
        sig_user_outer,
    })
}

/// Verify + AEAD-open + inner-verify a stored head pointer.
///
/// # Errors
///
/// `CryptoError::SignatureInvalid` for outer or inner sig failures;
/// `CryptoError::AeadOpen` for AEAD tampering / wrong key;
/// `CryptoError::KeyBlob` for malformed bytes (reused error variant
/// — could be its own variant in a follow-up).
pub fn open_head_pointer(
    user_enc_key: &AeadKey,
    identity_pk: &MlDsa65PublicKey,
    cluster_id: &ClusterId,
    user_id: &UserId,
    record_type: RecordType,
    stored: &StoredHeadPointer,
) -> Result<HeadPointer, CryptoError> {
    let outer = outer_signed_bytes(
        cluster_id,
        user_id,
        record_type,
        stored.seq,
        &stored.encrypted_pointer,
    );
    ml_dsa_65_verify(identity_pk, &stored.sig_user_outer, &outer)?;

    let aad = head_pointer_aad(cluster_id, user_id, record_type);
    let pt = open(user_enc_key, &stored.encrypted_pointer, &aad)?;
    let pointer: HeadPointer = cbor_from_slice(&pt)
        .map_err(|e| CryptoError::KeyBlob(format!("head pointer CBOR: {e}")))?;

    if pointer.seq != stored.seq {
        return Err(CryptoError::KeyBlob(format!(
            "head pointer seq mismatch: outer {} inner {}",
            stored.seq, pointer.seq
        )));
    }

    ml_dsa_65_verify(
        identity_pk,
        &pointer.sig_user_inner,
        &inner_signed_bytes(&pointer.snapshot_data_map, pointer.seq),
    )?;
    Ok(pointer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_dsa_65_keypair;

    fn user(byte: u8) -> UserId {
        UserId([byte; 16])
    }

    fn cluster(byte: u8) -> ClusterId {
        ClusterId([byte; 32])
    }

    fn fixture_dm() -> DataMap {
        DataMap(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee])
    }

    fn key() -> AeadKey {
        AeadKey::from_bytes([7u8; 32])
    }

    #[test]
    fn seal_open_round_trip() {
        let kp = ml_dsa_65_keypair().unwrap();
        let stored = seal_head_pointer(
            &key(),
            &kp.secret,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            fixture_dm(),
            42,
        )
        .unwrap();
        let opened = open_head_pointer(
            &key(),
            &kp.public,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            &stored,
        )
        .unwrap();
        assert_eq!(opened.snapshot_data_map, fixture_dm());
        assert_eq!(opened.seq, 42);
    }

    #[test]
    fn tampered_encrypted_pointer_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let mut stored = seal_head_pointer(
            &key(),
            &kp.secret,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            fixture_dm(),
            42,
        )
        .unwrap();
        let last = stored.encrypted_pointer.len() - 1;
        stored.encrypted_pointer[last] ^= 0x01;
        let err = open_head_pointer(
            &key(),
            &kp.public,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            &stored,
        )
        .unwrap_err();
        // Outer sig fails first (it commits to sha256(ct)).
        assert!(matches!(err, CryptoError::SignatureInvalid));
    }

    #[test]
    fn forged_outer_sig_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let mut stored = seal_head_pointer(
            &key(),
            &kp.secret,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            fixture_dm(),
            42,
        )
        .unwrap();
        stored.sig_user_outer.0[0] ^= 0x01;
        let err = open_head_pointer(
            &key(),
            &kp.public,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            &stored,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::SignatureInvalid));
    }

    #[test]
    fn wrong_record_type_in_aad_fails() {
        let kp = ml_dsa_65_keypair().unwrap();
        let stored = seal_head_pointer(
            &key(),
            &kp.secret,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            fixture_dm(),
            42,
        )
        .unwrap();
        // Open with a different record_type — both AAD and outer-sig
        // bind to it, so this must fail (whichever fails first).
        let err = open_head_pointer(
            &key(),
            &kp.public,
            &cluster(1),
            &user(2),
            RecordType::Alias,
            &stored,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CryptoError::SignatureInvalid | CryptoError::AeadOpen
        ));
    }

    #[test]
    fn substitution_at_different_seq_rejected() {
        // A malicious hub that tries to claim an old head pointer is
        // the "current" one for a different seq must fail: the outer
        // sig is bound to the exact seq.
        let kp = ml_dsa_65_keypair().unwrap();
        let mut stored = seal_head_pointer(
            &key(),
            &kp.secret,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            fixture_dm(),
            42,
        )
        .unwrap();
        stored.seq = 99;
        let err = open_head_pointer(
            &key(),
            &kp.public,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            &stored,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::SignatureInvalid));
    }

    #[test]
    fn wrong_user_in_aad_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let stored = seal_head_pointer(
            &key(),
            &kp.secret,
            &cluster(1),
            &user(2),
            RecordType::Credential,
            fixture_dm(),
            42,
        )
        .unwrap();
        let err = open_head_pointer(
            &key(),
            &kp.public,
            &cluster(1),
            &user(3),
            RecordType::Credential,
            &stored,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CryptoError::SignatureInvalid | CryptoError::AeadOpen
        ));
    }
}
