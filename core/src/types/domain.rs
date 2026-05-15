//! `Domain` record schema — unified namespace ownership.
//!
//! Both subdomain claims (`is_custom = false`, `base_domain =
//! Some(_)`) AND verified custom domains (`is_custom = true`,
//! `challenge = Some(_)` until verified) write the same `Domain`
//! record into the user's snapshot chain. The single record
//! type lets the alias module reference its `namespace` as a
//! plain string without needing to discriminate.
//!
//! No body face — every field fits comfortably in the metadata
//! face (always rides inline in the snapshot frame).

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::ProtocolError;
use crate::protocol::wire::domains::DomainStatus;
use crate::record::{RecordId, RecordType};
use crate::search::{Indexable, SearchHit};
use crate::types::FormatVersion;

/// Unified namespace-ownership record. Discriminated by
/// `is_custom`; subdomain claims and DNS-verified custom
/// domains write the same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainMetadata {
    pub format_version: FormatVersion,
    /// Full domain string the alias namespace lives under
    /// (e.g. `inbox-demo.vito.gg` or `example.com`).
    pub domain: String,
    /// `false` = subdomain claim under a managed base;
    /// `true` = user-owned domain DNS-verified by the hub.
    pub is_custom: bool,
    pub status: DomainStatus,
    /// Set when `status = Verified` / `Active`. `None` for
    /// pending custom domains and immediately `Some(now)` for
    /// fresh subdomain claims.
    pub verified_at_ms: Option<u64>,
    /// 32-byte challenge bytes from the hub's `add_custom_domain`
    /// flow. `Some` only while `is_custom = true && status =
    /// Pending`. `None` for subdomain claims (no DNS challenge
    /// needed).
    pub challenge: Option<[u8; 32]>,
    /// `Some(base)` for subdomain claims (the managed base
    /// domain the subdomain was claimed under); `None` for
    /// custom domains.
    pub base_domain: Option<String>,
    pub created_at_ms: u64,
}

impl DomainMetadata {
    /// Encode to deterministic CBOR for storage in a
    /// `MetadataField::Inline`.
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` if encoding fails.
    pub fn to_metadata_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        cbor_to_vec(self)
    }

    /// Decode from the bytes produced by [`Self::to_metadata_bytes`].
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` if the bytes are malformed.
    pub fn from_metadata_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        cbor_from_slice(bytes)
    }
}

impl Indexable for DomainMetadata {
    const RECORD_TYPE: RecordType = RecordType::Domain;

    fn from_metadata_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::from_metadata_bytes(bytes)
    }

    fn tokens(&self) -> Vec<Cow<'_, str>> {
        let mut out: Vec<Cow<'_, str>> = Vec::new();
        out.push(Cow::Borrowed(self.domain.as_str()));
        if let Some(base) = &self.base_domain {
            out.push(Cow::Borrowed(base.as_str()));
        }
        out
    }

    fn filter_keys(&self) -> Vec<(&'static str, Cow<'_, str>)> {
        let mut out: Vec<(&'static str, Cow<'_, str>)> = Vec::new();
        out.push((
            "kind",
            Cow::Borrowed(if self.is_custom { "custom" } else { "subdomain" }),
        ));
        out.push(("status", Cow::Borrowed(self.status.as_str())));
        out
    }

    fn build_hit(&self, record_id: RecordId) -> SearchHit {
        SearchHit {
            record_id,
            record_type: Self::RECORD_TYPE,
            title: self.domain.clone(),
            subtitle: Some(if self.is_custom {
                "custom domain".into()
            } else {
                "managed subdomain".into()
            }),
            score: 0.0,
        }
    }
}

impl DomainStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::INLINE_METADATA_MAX;

    fn fixture_subdomain() -> DomainMetadata {
        DomainMetadata {
            format_version: FormatVersion::V1,
            domain: "inbox-demo.vito.gg".into(),
            is_custom: false,
            status: DomainStatus::Active,
            verified_at_ms: Some(1_700_000_000_000),
            challenge: None,
            base_domain: Some("vito.gg".into()),
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn fixture_custom() -> DomainMetadata {
        DomainMetadata {
            format_version: FormatVersion::V1,
            domain: "example.com".into(),
            is_custom: true,
            status: DomainStatus::Pending,
            verified_at_ms: None,
            challenge: Some([0xab; 32]),
            base_domain: None,
            created_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn domain_metadata_round_trip_via_cbor_subdomain() {
        let m = fixture_subdomain();
        let bytes = m.to_metadata_bytes().unwrap();
        let back = DomainMetadata::from_metadata_bytes(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn domain_metadata_round_trip_via_cbor_custom() {
        let m = fixture_custom();
        let bytes = m.to_metadata_bytes().unwrap();
        let back = DomainMetadata::from_metadata_bytes(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn domain_metadata_fits_inline_threshold() {
        let m = fixture_subdomain();
        let n = m.to_metadata_bytes().unwrap().len();
        assert!(
            n <= INLINE_METADATA_MAX,
            "DomainMetadata encoded to {n} bytes; INLINE_METADATA_MAX \
             = {INLINE_METADATA_MAX}"
        );
    }

    #[test]
    fn domain_metadata_subdomain_variant_carries_base_domain() {
        let m = fixture_subdomain();
        assert_eq!(m.base_domain.as_deref(), Some("vito.gg"));
        assert!(!m.is_custom);
        assert!(m.challenge.is_none());
    }

    #[test]
    fn domain_metadata_custom_variant_carries_dns_challenge() {
        let m = fixture_custom();
        assert!(m.is_custom);
        assert!(m.base_domain.is_none());
        assert!(m.challenge.is_some());
    }

    #[test]
    fn domain_metadata_excludes_secret_field_names() {
        let m = fixture_subdomain();
        let v = serde_json::to_value(&m).unwrap();
        let banned: std::collections::HashSet<&str> =
            ["secret", "private_key", "passphrase", "password"]
                .into_iter()
                .collect();
        let keys = collect_object_keys(&v);
        for key in &keys {
            assert!(
                !banned.contains(key.to_ascii_lowercase().as_str()),
                "DomainMetadata field {key:?} matches a forbidden \
                 secret field name"
            );
        }
    }

    #[test]
    fn domain_metadata_indexable_tokens_include_domain_and_base() {
        let m = fixture_subdomain();
        let toks: Vec<String> = m.tokens().into_iter().map(|c| c.into_owned()).collect();
        assert!(toks.contains(&"inbox-demo.vito.gg".into()));
        assert!(toks.contains(&"vito.gg".into()));
    }

    #[test]
    fn domain_metadata_filter_keys_carry_kind_and_status() {
        let m = fixture_subdomain();
        let keys: Vec<(String, String)> = m
            .filter_keys()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect();
        assert!(keys.contains(&("kind".into(), "subdomain".into())));
        assert!(keys.contains(&("status".into(), "active".into())));

        let m2 = fixture_custom();
        let keys2: Vec<(String, String)> = m2
            .filter_keys()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect();
        assert!(keys2.contains(&("kind".into(), "custom".into())));
        assert!(keys2.contains(&("status".into(), "pending".into())));
    }

    #[test]
    fn domain_metadata_build_hit_distinguishes_subdomain_from_custom() {
        assert_eq!(
            fixture_subdomain().build_hit(RecordId([0u8; 16])).subtitle,
            Some("managed subdomain".into())
        );
        assert_eq!(
            fixture_custom().build_hit(RecordId([0u8; 16])).subtitle,
            Some("custom domain".into())
        );
    }

    fn collect_object_keys(v: &serde_json::Value) -> Vec<String> {
        let mut out = Vec::new();
        match v {
            serde_json::Value::Object(map) => {
                for (k, child) in map {
                    out.push(k.clone());
                    out.extend(collect_object_keys(child));
                }
            }
            serde_json::Value::Array(arr) => {
                for child in arr {
                    out.extend(collect_object_keys(child));
                }
            }
            _ => {}
        }
        out
    }
}
