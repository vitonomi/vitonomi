//! User-facing record types and the high-level snapshot-chain API.
//!
//! A **record** is the smallest user-data unit (a credential, an
//! alias, a single email message, eventually a photo). Records are
//! grouped by [`RecordType`] and chained into signed, AEAD-sealed,
//! self-encrypted snapshots. The latest snapshot's DataMap lives
//! inline in the per-record-type head pointer; the head pointer
//! is itself AEAD-encrypted and stored on the hub, in IndexedDB,
//! and in the seed-phrase backup file.
//!
//! Each record has **two faces**: a small searchable **metadata
//! face** (always pulled by browse / list / search) and an optional
//! larger **body face** (pulled lazily when the user opens the
//! record). The metadata face rides inline in the snapshot's
//! RecordFrame whenever the encoded CBOR is ≤ [`INLINE_METADATA_MAX`]
//! bytes; otherwise it is sealed as a separate blob and the frame
//! holds a DataMap pointer. The body face is always sealed as a
//! separate blob (or absent for records whose entire content fits
//! in the metadata face).
//!
//! Encryption pipeline for the inline-metadata case:
//!
//! ```text
//! signed_snapshot ──AEAD(user_record_key)──▶ ciphertext ──self_encryption──▶ chunks + DataMap
//! ```
//!
//! Encryption pipeline for blob-metadata and body faces:
//!
//! ```text
//! plaintext ──AEAD(user_record_key, face_AAD)──▶ ciphertext ──self_encryption──▶ chunks + DataMap
//! ```
//!
//! The AEAD step uses a per-(user, record_type) key derived from
//! [`user_keys::derive_record_aead_key`]. The metadata blob and the
//! body blob share the same key but are bound to distinct
//! AAD prefixes ([`record_metadata_aad`] vs [`record_body_aad`]) so a
//! ciphertext is cryptographically tied to its face and to its
//! `record_id` — a malicious vault cannot substitute one face for
//! another or cross records.

use serde::{Deserialize, Serialize};

use crate::crypto::selfencrypt::DataMap;
use crate::errors::ValidationError;
use crate::types::UserId;

pub mod head_pointer;
pub mod record_store;
pub mod snapshot;
pub mod user_keys;

/// Maximum CBOR-encoded length, in bytes, of a metadata face that
/// may ride **inline** inside a [`snapshot::RecordFrame`]. Anything
/// longer is sealed as a separate metadata blob and the frame
/// stores its DataMap. Inline is the common case: it lets `list` /
/// `search` stay one-fetch-per-snapshot.
pub const INLINE_METADATA_MAX: usize = 512;

/// One face of a record carried inside a [`snapshot::RecordFrame`].
///
/// `Inline` rides directly in the snapshot envelope (no separate
/// sealing step); `Blob` references chunks of a separately-sealed
/// metadata blob via its DataMap. Readers MUST accept either
/// variant on any record; writers SHOULD prefer `Inline` whenever
/// the encoded metadata fits within [`INLINE_METADATA_MAX`].
///
/// Wire layout — see `docs/data-format.md#recordframe`. CBOR-tagged
/// union with serde-style internal tagging on the `kind` field:
/// `{ "kind": "inline", "bytes": <bytes(var)> }` or
/// `{ "kind": "blob", "data_map": <bytes(var)> }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MetadataField {
    /// Encoded metadata bytes carried directly in the RecordFrame.
    /// Length MUST be ≤ [`INLINE_METADATA_MAX`].
    Inline {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    /// DataMap pointing to the chunks of a separately-sealed metadata
    /// blob. Sealed under the per-(user, record_type) AEAD key with
    /// AAD built by [`record_metadata_aad`].
    Blob { data_map: DataMap },
}

/// AAD prefix used when AEAD-sealing a separately-stored metadata
/// blob ([`MetadataField::Blob`]). Bound to `(user_id, record_type,
/// record_id)` so a ciphertext cannot be substituted across records,
/// across faces, or across users.
const RECORD_METADATA_AAD_PREFIX: &[u8] = b"vitonomi/record_metadata/v1";

/// AAD prefix used when AEAD-sealing a record body face. Same binding
/// rules as [`record_metadata_aad`]; the distinct prefix prevents
/// cross-face substitution under a shared per-(user, record_type)
/// key.
const RECORD_BODY_AAD_PREFIX: &[u8] = b"vitonomi/record_body/v1";

/// Build the AAD bytes used when AEAD-sealing a metadata blob.
///
/// ```text
/// b"vitonomi/record_metadata/v1" || user_id(16) || record_type(1) || record_id(16)
/// ```
#[must_use]
pub fn record_metadata_aad(
    user_id: UserId,
    record_type: RecordType,
    record_id: RecordId,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_METADATA_AAD_PREFIX.len() + 16 + 1 + 16);
    aad.extend_from_slice(RECORD_METADATA_AAD_PREFIX);
    aad.extend_from_slice(&user_id.0);
    aad.push(record_type.as_u8());
    aad.extend_from_slice(&record_id.0);
    aad
}

/// Build the AAD bytes used when AEAD-sealing a record body face.
///
/// ```text
/// b"vitonomi/record_body/v1" || user_id(16) || record_type(1) || record_id(16)
/// ```
#[must_use]
pub fn record_body_aad(user_id: UserId, record_type: RecordType, record_id: RecordId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_BODY_AAD_PREFIX.len() + 16 + 1 + 16);
    aad.extend_from_slice(RECORD_BODY_AAD_PREFIX);
    aad.extend_from_slice(&user_id.0);
    aad.push(record_type.as_u8());
    aad.extend_from_slice(&record_id.0);
    aad
}

/// Per-record-type discriminator. The u8 byte assignments are
/// **wire-stable** and documented in `docs/data-format.md` v0.4.
///
/// MVP record types: `Credential`, `Alias`, `AliasMessage`,
/// `Domain`. Reserved (parse-error in V1 readers): `Photo = 0x10`,
/// `Note = 0x20`, `File = 0x30`. Unused bytes in `0x05..=0x0f`
/// are reserved for future expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecordType {
    Credential,
    Alias,
    AliasMessage,
    /// Phase 7 Slice 6: namespace ownership records. Both
    /// `subdomain claim` (under a managed base) and `domain
    /// add` (custom DNS-verified) write the same `Domain`
    /// record discriminated by an `is_custom` flag on the
    /// metadata. See `core::types::domain::DomainMetadata`.
    Domain,
}

impl RecordType {
    /// Stable u8 discriminator used as wire byte and in AEAD AAD.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Credential => 0x01,
            Self::Alias => 0x02,
            Self::AliasMessage => 0x03,
            Self::Domain => 0x04,
        }
    }

    /// Parse a u8 wire byte back to a `RecordType`. Reserved values
    /// (e.g. 0x10 / 0x20 / 0x30) are rejected.
    ///
    /// # Errors
    ///
    /// `ValidationError::Other` for unknown / reserved discriminators.
    pub fn from_u8(byte: u8) -> Result<Self, ValidationError> {
        match byte {
            0x01 => Ok(Self::Credential),
            0x02 => Ok(Self::Alias),
            0x03 => Ok(Self::AliasMessage),
            0x04 => Ok(Self::Domain),
            other => Err(ValidationError::Other(format!(
                "unknown / reserved RecordType: 0x{other:02x}"
            ))),
        }
    }
}

/// Opaque random per-record identifier. Generated client-side; never
/// derived from content (deriving from content would leak record
/// equality across users).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordId(pub [u8; 16]);

impl RecordId {
    /// Generate a fresh random record id from the platform RNG.
    ///
    /// # Errors
    ///
    /// `CryptoError::Random` if the platform RNG fails.
    pub fn generate() -> Result<Self, crate::errors::CryptoError> {
        let mut out = [0u8; 16];
        crate::crypto::random::fill_random(&mut out)?;
        Ok(Self(out))
    }

    /// Hex string for human-friendly display + CLI args.
    #[must_use]
    pub fn to_hex(self) -> String {
        crate::encoding::hex_encode(&self.0)
    }

    /// Parse a hex string back to a `RecordId`.
    ///
    /// # Errors
    ///
    /// `ValidationError::Other` if the hex is malformed or not 32
    /// nibbles.
    pub fn from_hex(s: &str) -> Result<Self, ValidationError> {
        let bytes = crate::encoding::hex_decode(s.trim())
            .map_err(|e| ValidationError::Other(format!("RecordId hex: {e}")))?;
        let arr: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ValidationError::Other("RecordId must be 16 bytes".into()))?;
        Ok(Self(arr))
    }
}

impl std::fmt::Display for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Where a snapshot's chunks should be replicated to. Typed-and-
/// closed: future tiers require a `format_version` bump rather than
/// a silent enum extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupTarget {
    /// vitonomi-vault chunk store (always in MVP).
    Vault,
    /// Autonomi network (v1.1+; parse-error on read in V1).
    Autonomi,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_round_trip() {
        for rt in [
            RecordType::Credential,
            RecordType::Alias,
            RecordType::AliasMessage,
            RecordType::Domain,
        ] {
            let byte = rt.as_u8();
            assert_eq!(RecordType::from_u8(byte).unwrap(), rt);
        }
    }

    #[test]
    fn record_type_rejects_reserved_bytes() {
        // Phase 7 promotes 0x04 to `Domain`. New reserved set:
        // 0x00, 0x05..=0x0f, 0x10, 0x20, 0x30, 0xff.
        for byte in [0x00u8, 0x05, 0x0f, 0x10, 0x20, 0x30, 0xff] {
            assert!(RecordType::from_u8(byte).is_err(), "byte {byte:#x}");
        }
    }

    #[test]
    fn record_id_generate_is_random() {
        let a = RecordId::generate().unwrap();
        let b = RecordId::generate().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn record_id_hex_round_trip() {
        let id = RecordId::generate().unwrap();
        let s = id.to_hex();
        assert_eq!(s.len(), 32);
        assert_eq!(RecordId::from_hex(&s).unwrap(), id);
    }

    #[test]
    fn metadata_field_inline_round_trip_via_cbor() {
        let mf = MetadataField::Inline {
            bytes: b"some metadata".to_vec(),
        };
        let cbor = crate::encoding::cbor_to_vec(&mf).unwrap();
        let back: MetadataField = crate::encoding::cbor_from_slice(&cbor).unwrap();
        assert_eq!(back, mf);
    }

    #[test]
    fn metadata_field_blob_round_trip_via_cbor() {
        let mf = MetadataField::Blob {
            data_map: DataMap(vec![1, 2, 3, 4, 5]),
        };
        let cbor = crate::encoding::cbor_to_vec(&mf).unwrap();
        let back: MetadataField = crate::encoding::cbor_from_slice(&cbor).unwrap();
        assert_eq!(back, mf);
    }

    #[test]
    fn metadata_aad_distinct_from_body_aad() {
        let uid = UserId([1; 16]);
        let rid = RecordId([2; 16]);
        let m = record_metadata_aad(uid, RecordType::Credential, rid);
        let b = record_body_aad(uid, RecordType::Credential, rid);
        assert_ne!(m, b, "metadata and body AADs must differ for the same record");
    }

    #[test]
    fn metadata_aad_distinct_per_user() {
        let m1 = record_metadata_aad(UserId([1; 16]), RecordType::Credential, RecordId([0; 16]));
        let m2 = record_metadata_aad(UserId([2; 16]), RecordType::Credential, RecordId([0; 16]));
        assert_ne!(m1, m2);
    }

    #[test]
    fn metadata_aad_distinct_per_record_type() {
        let m1 = record_metadata_aad(UserId([1; 16]), RecordType::Credential, RecordId([0; 16]));
        let m2 = record_metadata_aad(UserId([1; 16]), RecordType::Alias, RecordId([0; 16]));
        assert_ne!(m1, m2);
    }

    #[test]
    fn metadata_aad_distinct_per_record_id() {
        let m1 = record_metadata_aad(UserId([1; 16]), RecordType::Credential, RecordId([7; 16]));
        let m2 = record_metadata_aad(UserId([1; 16]), RecordType::Credential, RecordId([8; 16]));
        assert_ne!(m1, m2);
    }
}
