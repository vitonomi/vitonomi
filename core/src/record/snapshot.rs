//! Snapshot envelope: a signed, batched, AEAD-sealed-then-self-
//! encrypted record-of-record-ops.
//!
//! Layered:
//!
//! 1. `Snapshot` (plaintext, serde-CBOR) — what the user actually
//!    edits.
//! 2. `SignedSnapshot` (Snapshot + ML-DSA-65 signature over its
//!    CBOR) — the on-the-wire form, still plaintext at the AEAD layer.
//! 3. AEAD ciphertext under
//!    [`crate::record::user_keys::derive_record_aead_key`].
//!    AAD: `b"vitonomi/snapshot/v1" || user_id(16) || record_type(1)
//!    || seq_be8`.
//! 4. Self-encrypted via [`crate::crypto::selfencrypt::encrypt`].
//!    Output: a `Vec<Chunk>` + a `DataMap`. The `DataMap` rides
//!    inline in the head pointer; chunks land on the vault chunk
//!    store.

use serde::{Deserialize, Serialize};

use crate::crypto::pq::{
    ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
};
use crate::crypto::selfencrypt::DataMap;
use crate::encoding::cbor_to_vec;
use crate::errors::CryptoError;
use crate::protocol::autonomi_bridge::ChunkAddress;
use crate::record::{BackupTarget, MetadataField, RecordId, RecordType};
use crate::types::FormatVersion;

/// What happened to a record in this snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "op")]
pub enum RecordOp {
    /// New value (insert or update). Carries the record's metadata
    /// face (inline or by DataMap) and an optional `body_data_map`
    /// pointing at the separately-sealed body face. Records without
    /// a body face omit `body_data_map`.
    Put {
        /// The record's searchable metadata face. See
        /// [`crate::record::MetadataField`].
        metadata: MetadataField,
        /// DataMap pointing to the chunks of the AEAD-sealed body
        /// face, or `None` for records without a body. Sealed under
        /// AAD built by [`crate::record::record_body_aad`].
        body_data_map: Option<DataMap>,
    },
    /// Tombstone. The record is gone after this seq.
    Delete,
}

/// One record-level entry inside a snapshot. The cumulative-frames
/// snapshot model (slice 1 / MVP): each new snapshot carries every
/// frame for the record_type, with the latest frame per record_id
/// winning. Compaction is a v1.1 follow-up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordFrame {
    pub record_id: RecordId,
    pub op: RecordOp,
    /// Monotonic per-record version; lets a future N-writer model
    /// detect concurrent edits. The single-writer slice keeps this
    /// strictly increasing per record.
    pub prev_record_version: u64,
}

/// Plaintext snapshot envelope. Signed by the user identity sk;
/// AEAD-encrypted before self-encryption; chunked + addressed by
/// the chunk store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub format_version: FormatVersion,
    pub record_type: RecordType,
    pub seq: u64,
    /// First chunk address of the previous snapshot in this chain,
    /// or `None` for the genesis snapshot.
    pub prev_address: Option<ChunkAddress>,
    pub frames: Vec<RecordFrame>,
    /// Where chunks should be replicated to. MVP: always `[Vault]`.
    pub backup_targets: Vec<BackupTarget>,
}

/// Snapshot + ML-DSA-65 signature over its canonical CBOR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSnapshot {
    pub snapshot: Snapshot,
    pub sig_user: MlDsa65Signature,
}

/// Sign a snapshot. Caller has already populated the
/// `frames` + `seq` + `prev_address` fields and is locking in their
/// commitment to them.
///
/// # Errors
///
/// `CryptoError::Signature` from ML-DSA, or `CryptoError::Kdf` if
/// CBOR encoding fails.
pub fn sign_snapshot(
    identity_sk: &MlDsa65SecretKey,
    snapshot: Snapshot,
) -> Result<SignedSnapshot, CryptoError> {
    let msg =
        cbor_to_vec(&snapshot).map_err(|e| CryptoError::Kdf(format!("snapshot CBOR: {e}")))?;
    let sig = ml_dsa_65_sign(identity_sk, &msg)?;
    Ok(SignedSnapshot {
        snapshot,
        sig_user: sig,
    })
}

/// Verify a snapshot signature.
///
/// # Errors
///
/// `CryptoError::SignatureInvalid` if the signature doesn't verify,
/// or `CryptoError::Kdf` if CBOR encoding fails (shouldn't happen
/// for a well-formed value).
pub fn verify_snapshot(
    identity_pk: &MlDsa65PublicKey,
    signed: &SignedSnapshot,
) -> Result<(), CryptoError> {
    let msg = cbor_to_vec(&signed.snapshot)
        .map_err(|e| CryptoError::Kdf(format!("snapshot CBOR: {e}")))?;
    ml_dsa_65_verify(identity_pk, &signed.sig_user, &msg)
}

/// Build the AEAD AAD for a snapshot envelope. Binds `user_id +
/// record_type + seq` into the seal so a malicious hub cannot
/// substitute one snapshot for another at the same address.
#[must_use]
pub fn snapshot_aad(user_id: crate::types::UserId, record_type: RecordType, seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(24 + 16 + 1 + 8);
    aad.extend_from_slice(b"vitonomi/snapshot/v1");
    aad.extend_from_slice(&user_id.0);
    aad.push(record_type.as_u8());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_dsa_65_keypair;

    fn sample_snapshot(seq: u64) -> Snapshot {
        Snapshot {
            format_version: FormatVersion::V1,
            record_type: RecordType::Credential,
            seq,
            prev_address: None,
            frames: vec![RecordFrame {
                record_id: RecordId([1u8; 16]),
                op: RecordOp::Put {
                    metadata: MetadataField::Inline {
                        bytes: b"sample-metadata".to_vec(),
                    },
                    body_data_map: Some(DataMap(vec![0xaa, 0xbb])),
                },
                prev_record_version: 0,
            }],
            backup_targets: vec![BackupTarget::Vault],
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let kp = ml_dsa_65_keypair().unwrap();
        let snap = sample_snapshot(1);
        let signed = sign_snapshot(&kp.secret, snap).unwrap();
        verify_snapshot(&kp.public, &signed).unwrap();
    }

    #[test]
    fn tampered_snapshot_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let snap = sample_snapshot(1);
        let mut signed = sign_snapshot(&kp.secret, snap).unwrap();
        // Mutate one frame.
        signed.snapshot.frames[0].prev_record_version = 999;
        assert!(matches!(
            verify_snapshot(&kp.public, &signed),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn cross_key_rejected() {
        let kp1 = ml_dsa_65_keypair().unwrap();
        let kp2 = ml_dsa_65_keypair().unwrap();
        let snap = sample_snapshot(1);
        let signed = sign_snapshot(&kp1.secret, snap).unwrap();
        assert!(matches!(
            verify_snapshot(&kp2.public, &signed),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn genesis_has_no_prev_address() {
        let snap = sample_snapshot(0);
        assert!(snap.prev_address.is_none());
    }

    #[test]
    fn cbor_round_trip() {
        let kp = ml_dsa_65_keypair().unwrap();
        let signed = sign_snapshot(&kp.secret, sample_snapshot(7)).unwrap();
        let bytes = cbor_to_vec(&signed).unwrap();
        let back: SignedSnapshot = crate::encoding::cbor_from_slice(&bytes).unwrap();
        assert_eq!(back, signed);
        verify_snapshot(&kp.public, &back).unwrap();
    }

    #[test]
    fn aad_includes_user_record_type_and_seq() {
        let aad_a = snapshot_aad(crate::types::UserId([1u8; 16]), RecordType::Credential, 5);
        let aad_b = snapshot_aad(crate::types::UserId([1u8; 16]), RecordType::Credential, 6);
        let aad_c = snapshot_aad(crate::types::UserId([1u8; 16]), RecordType::Alias, 5);
        let aad_d = snapshot_aad(crate::types::UserId([2u8; 16]), RecordType::Credential, 5);
        assert_ne!(aad_a, aad_b, "seq differs");
        assert_ne!(aad_a, aad_c, "record_type differs");
        assert_ne!(aad_a, aad_d, "user differs");
    }
}
