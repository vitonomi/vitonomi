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
//! Encryption pipeline for each record / snapshot:
//!
//! ```text
//! plaintext ──AEAD(user_record_key)──▶ ciphertext ──self_encryption──▶ chunks + DataMap
//! ```
//!
//! The AEAD step uses a per-(user, record_type) key derived from
//! [`user_keys::derive_record_aead_key`]; this breaks the natural
//! convergence of self-encryption and prevents confirmation-of-file
//! attacks.

use serde::{Deserialize, Serialize};

use crate::errors::ValidationError;

pub mod head_pointer;
pub mod record_store;
pub mod snapshot;
pub mod user_keys;

/// Per-record-type discriminator. The u8 byte assignments are
/// **wire-stable** and documented in `docs/data-format.md` v0.2.
///
/// MVP record types: `Credential`, `Alias`, `AliasMessage`.
/// Reserved (parse-error in V1 readers): `Photo = 0x10`,
/// `Note = 0x20`, `File = 0x30`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecordType {
    Credential,
    Alias,
    AliasMessage,
}

impl RecordType {
    /// Stable u8 discriminator used as wire byte and in AEAD AAD.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Credential => 0x01,
            Self::Alias => 0x02,
            Self::AliasMessage => 0x03,
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
        ] {
            let byte = rt.as_u8();
            assert_eq!(RecordType::from_u8(byte).unwrap(), rt);
        }
    }

    #[test]
    fn record_type_rejects_reserved_bytes() {
        for byte in [0x00u8, 0x04, 0x10, 0x20, 0x30, 0xff] {
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
}
