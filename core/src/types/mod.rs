//! Shared branded primitives + per-RecordType data schemas.
//!
//! Primitives (`FormatVersion`, `ClusterId`, `UserId`, `VaultId`,
//! `SessionToken`, `Username`) live here. Per-RecordType `*Metadata`
//! / `*Body` schemas live in submodules (`credential`, …) — see
//! `docs/record-types.md`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::errors::ValidationError;

pub mod credential;

/// Wire-format version. Carried in every top-level envelope so readers
/// reject mismatched-version bytes with a typed error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FormatVersion(pub u8);

impl FormatVersion {
    pub const V1: Self = Self(1);

    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

impl fmt::Display for FormatVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Cluster identifier. Derived from the cluster admin's ML-DSA-65
/// public key + format version: `cluster_id =
/// sha256(admin_pubkey || format_version)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClusterId(pub [u8; 32]);

impl ClusterId {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ClusterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// User identifier. UUIDv4-like 16-byte random value assigned by the
/// hub on registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub [u8; 16]);

/// Vault identifier. Random 16-byte value assigned by the hub on
/// vault enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VaultId(pub [u8; 16]);

/// Opaque session token (32 bytes encoded as URL-safe base64 on the
/// wire). The hub stores `sha256(token)`, never the raw token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionToken(pub String);

impl fmt::Display for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print only first 8 chars in case Display ends up in a log.
        let prefix: String = self.0.chars().take(8).collect();
        write!(f, "{prefix}…")
    }
}

/// User-chosen handle. Lowercase ASCII alphanumeric + `-` + `_`,
/// length 3–32, case-insensitive at storage. DNS-safe by construction
/// so a future `<username>.vito.gg` subdomain works without
/// renormalisation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Username(String);

impl Username {
    /// Parse a username. Returns [`ValidationError::InvalidUsername`]
    /// if the input violates the format rules.
    ///
    /// Rules:
    /// - Length 3–32 ASCII characters (post-trim, post-lowercase).
    /// - Allowed character class: `[a-z0-9_-]`.
    ///
    /// # Errors
    ///
    /// Returns `ValidationError::InvalidUsername` with a reason string
    /// when any rule is violated.
    pub fn parse(input: &str) -> Result<Self, ValidationError> {
        let trimmed = input.trim();
        let lower = trimmed.to_ascii_lowercase();

        if lower.len() < 3 {
            return Err(ValidationError::InvalidUsername("too short (min 3)".into()));
        }
        if lower.len() > 32 {
            return Err(ValidationError::InvalidUsername("too long (max 32)".into()));
        }
        for (i, c) in lower.chars().enumerate() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
                return Err(ValidationError::InvalidUsername(format!(
                    "illegal character at position {i}: {c:?}"
                )));
            }
        }

        Ok(Self(lower))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Username {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Result type alias used across vitonomi where errors flow through
/// the typed hierarchy in [`crate::errors`].
pub type Result<T, E = crate::errors::CoreError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_accepts_typical_inputs() {
        assert_eq!(Username::parse("birkeal").unwrap().as_str(), "birkeal");
        assert_eq!(Username::parse("pi_node").unwrap().as_str(), "pi_node");
        assert_eq!(Username::parse("family-1").unwrap().as_str(), "family-1");
        assert_eq!(Username::parse("a1b2").unwrap().as_str(), "a1b2");
    }

    #[test]
    fn username_lowercases_input() {
        assert_eq!(Username::parse("BIRKEAL").unwrap().as_str(), "birkeal");
        assert_eq!(Username::parse("Pi_Node").unwrap().as_str(), "pi_node");
    }

    #[test]
    fn username_trims_input() {
        assert_eq!(Username::parse("  birkeal  ").unwrap().as_str(), "birkeal");
    }

    #[test]
    fn username_rejects_too_short() {
        assert!(matches!(
            Username::parse("ab"),
            Err(ValidationError::InvalidUsername(_))
        ));
        assert!(matches!(
            Username::parse(""),
            Err(ValidationError::InvalidUsername(_))
        ));
    }

    #[test]
    fn username_rejects_too_long() {
        let s: String = "a".repeat(33);
        assert!(matches!(
            Username::parse(&s),
            Err(ValidationError::InvalidUsername(_))
        ));
    }

    #[test]
    fn username_rejects_illegal_chars() {
        for bad in [
            "birkeal!",
            "bir keal",
            "bir.keal",
            "bir/keal",
            "bir\\keal",
            "bir@keal",
            "büerkel",
            "пользователь",
        ] {
            assert!(
                matches!(
                    Username::parse(bad),
                    Err(ValidationError::InvalidUsername(_))
                ),
                "expected rejection for {bad:?}"
            );
        }
    }
}
