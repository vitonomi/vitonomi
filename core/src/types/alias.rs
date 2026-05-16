//! Alias schemas — the mail-receiving primitive.
//!
//! Each alias is one email address (`<alias_handle>@<namespace>`)
//! with its own ML-KEM-768 keypair. The mx relay encrypts inbound
//! mail to the alias's published pubkey via
//! [`crate::crypto::alias_inbound`]; the user fetches ciphertext
//! envelopes from the per-alias inbound queue and decapsulates with
//! the alias secret key from [`AliasBody`].
//!
//! The `namespace` field is a plain `String` (the full domain
//! the address lives under, e.g. `inbox-demo.vito.gg` or
//! `example.com`). Discrimination between vitonomi-managed
//! subdomains and user-owned DNS-verified domains lives on the
//! `Domain` record type — the alias does not need to know.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::crypto::keys::MlKem768SecretKeyBytes;
use crate::crypto::pq::{MlDsa65Signature, MlKem768PublicKey};
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::{ProtocolError, ValidationError};
use crate::record::{RecordId, RecordType};
use crate::search::{Indexable, SearchHit};
use crate::types::FormatVersion;

/// Searchable / browseable face of an alias record. Carried
/// inline in the snapshot frame; holds **no decapsulation key**
/// — the secret half lives on [`AliasBody`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasMetadata {
    pub format_version: FormatVersion,
    /// 16-byte hint the client uses to derive the canonical
    /// `record_id` for this alias — kept as a metadata field
    /// (not just relying on the RecordFrame's id) so a
    /// snapshot-rebuild can verify identity even after a frame
    /// reorder.
    pub alias_id_hint: [u8; 16],
    /// Local part of the email address (e.g. `netflix` in
    /// `netflix@inbox-demo.vito.gg`).
    pub alias_handle: String,
    /// Full domain the address lives under (e.g.
    /// `inbox-demo.vito.gg` or `example.com`).
    pub namespace: String,
    /// Optional human label.
    pub label: Option<String>,
    /// ML-KEM-768 public key the mx relay encrypts inbound mail
    /// to. The matching secret key lives in [`AliasBody`].
    pub alias_kem_pubkey: MlKem768PublicKey,
    /// User signature binding the pubkey to this alias slot
    /// under the user's identity sk. Lets a fetcher verify the
    /// pubkey wasn't substituted by a malicious vault between
    /// publish and read.
    pub sig_user_over_pubkey: MlDsa65Signature,
    pub expiry_ms: Option<u64>,
    pub active: bool,
    pub spam_policy: SpamPolicy,
    pub tags: Vec<String>,
    pub last_used_at_ms: Option<u64>,
    pub created_at_ms: u64,
}

/// Inbound-mail acceptance policy. Wired into the mx relay's
/// RCPT-time decision (along with SPF/DKIM/DMARC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpamPolicy {
    /// Accept any sender. Default.
    OpenInbox,
    /// Reject senders not on the alias's allow-list.
    RequireSenderAllowList,
    /// Reject senders that fail SPF / DKIM / DMARC.
    RequireSpfDmarcPass,
}

/// Secret face of an alias — the ML-KEM-768 decapsulation key
/// only the user can hold. Sealed as a separate body blob; only
/// fetched when the user opens the alias inbox.
///
/// Stores the wire-form [`MlKem768SecretKeyBytes`] (64-byte
/// FIPS 203 seed, `ZeroizeOnDrop`); convert to a usable
/// `MlKem768SecretKey` via `into_secret_key()` at decap time.
/// `Debug` and `PartialEq` are deliberately NOT derived to
/// minimise accidental secret-leak surfaces (mirrors
/// `crate::crypto::keys::MasterSecretKeys`).
#[derive(Clone, Serialize, Deserialize)]
pub struct AliasBody {
    pub format_version: FormatVersion,
    pub alias_kem_secret_key: MlKem768SecretKeyBytes,
}

impl AliasMetadata {
    /// Encode to deterministic CBOR for storage in a
    /// `MetadataField::Inline` (or sealing as a Blob if oversize).
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

    /// Reconstruct the user-facing email address.
    #[must_use]
    pub fn full_address(&self) -> String {
        format!("{}@{}", self.alias_handle, self.namespace)
    }

    /// Parse a `local@domain` string into `(alias_handle,
    /// namespace)`. Splits on the **rightmost** `@` so unusual
    /// (RFC-legal) local parts that contain `@` round-trip; the
    /// vast majority of inputs have one `@`.
    ///
    /// # Errors
    ///
    /// `ValidationError::Other` for missing `@`, empty
    /// alias_handle, or empty namespace. The domain is not
    /// validated for DNS legality here — that's the mx relay's
    /// concern at RCPT time and the hub's concern at directory
    /// publish time.
    pub fn parse_address(s: &str) -> Result<(String, String), ValidationError> {
        let s = s.trim();
        let (local, domain) = s
            .rsplit_once('@')
            .ok_or_else(|| ValidationError::Other(format!("address missing '@': {s:?}")))?;
        if local.is_empty() {
            return Err(ValidationError::Other(format!(
                "address has empty local part: {s:?}"
            )));
        }
        if domain.is_empty() {
            return Err(ValidationError::Other(format!(
                "address has empty domain part: {s:?}"
            )));
        }
        Ok((local.to_string(), domain.to_ascii_lowercase()))
    }
}

impl AliasBody {
    /// Encode to deterministic CBOR for sealing as a body blob.
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` if encoding fails.
    pub fn to_body_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        cbor_to_vec(self)
    }

    /// Decode from the bytes produced by [`Self::to_body_bytes`].
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` if the bytes are malformed.
    pub fn from_body_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        cbor_from_slice(bytes)
    }
}

impl Indexable for AliasMetadata {
    const RECORD_TYPE: RecordType = RecordType::Alias;

    fn from_metadata_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::from_metadata_bytes(bytes)
    }

    fn tokens(&self) -> Vec<Cow<'_, str>> {
        let mut out: Vec<Cow<'_, str>> = Vec::new();
        out.push(Cow::Borrowed(self.alias_handle.as_str()));
        out.push(Cow::Borrowed(self.namespace.as_str()));
        // Push the full address as one token so users searching
        // "netflix@inbox-demo" get a hit.
        out.push(Cow::Owned(self.full_address()));
        if let Some(label) = &self.label {
            out.push(Cow::Borrowed(label.as_str()));
        }
        for tag in &self.tags {
            out.push(Cow::Borrowed(tag.as_str()));
        }
        out
    }

    fn filter_keys(&self) -> Vec<(&'static str, Cow<'_, str>)> {
        let mut out: Vec<(&'static str, Cow<'_, str>)> = Vec::new();
        out.push(("namespace", Cow::Borrowed(self.namespace.as_str())));
        out.push((
            "active",
            Cow::Borrowed(if self.active { "true" } else { "false" }),
        ));
        for tag in &self.tags {
            out.push(("tag", Cow::Borrowed(tag.as_str())));
        }
        out
    }

    fn build_hit(&self, record_id: RecordId) -> SearchHit {
        SearchHit {
            record_id,
            record_type: Self::RECORD_TYPE,
            title: self
                .label
                .clone()
                .unwrap_or_else(|| self.full_address()),
            subtitle: Some(self.full_address()),
            score: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::{ml_dsa_65_keypair, ml_dsa_65_sign, ml_kem_768_keypair};
    use crate::record::INLINE_METADATA_MAX;

    fn fixture_metadata() -> AliasMetadata {
        let kem = ml_kem_768_keypair().unwrap();
        let dsa = ml_dsa_65_keypair().unwrap();
        let sig = ml_dsa_65_sign(&dsa.secret, &kem.public.0).unwrap();
        AliasMetadata {
            format_version: FormatVersion::V1,
            alias_id_hint: [7u8; 16],
            alias_handle: "netflix".into(),
            namespace: "inbox-demo.vito.gg".into(),
            label: Some("Streaming".into()),
            alias_kem_pubkey: kem.public,
            sig_user_over_pubkey: sig,
            expiry_ms: None,
            active: true,
            spam_policy: SpamPolicy::OpenInbox,
            tags: vec!["streaming".into(), "shared".into()],
            last_used_at_ms: None,
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn fixture_body() -> AliasBody {
        let kem = ml_kem_768_keypair().unwrap();
        AliasBody {
            format_version: FormatVersion::V1,
            alias_kem_secret_key: MlKem768SecretKeyBytes(kem.secret.0.clone()),
        }
    }

    // ── Round-trip ────────────────────────────────────────────

    #[test]
    fn alias_metadata_round_trip_via_cbor() {
        let m = fixture_metadata();
        let bytes = m.to_metadata_bytes().unwrap();
        let back = AliasMetadata::from_metadata_bytes(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn alias_body_round_trip_via_cbor() {
        let b = fixture_body();
        let bytes = b.to_body_bytes().unwrap();
        let back = AliasBody::from_body_bytes(&bytes).unwrap();
        // AliasBody intentionally lacks PartialEq (mirrors
        // MasterSecretKeys); compare via the inner byte fields.
        assert_eq!(back.format_version, b.format_version);
        assert_eq!(back.alias_kem_secret_key.0, b.alias_kem_secret_key.0);
    }

    // ── Inline-threshold property ─────────────────────────────

    #[test]
    fn alias_metadata_fits_inline_threshold() {
        // Realistic alias: 32-char handle, 64-char namespace,
        // 32-char label, 4 tags. ML-KEM-768 pubkey + ML-DSA-65
        // signature dominate the size budget — verify the rest
        // doesn't push over INLINE_METADATA_MAX.
        let mut m = fixture_metadata();
        m.alias_handle = "x".repeat(32);
        m.namespace = "y".repeat(64);
        m.label = Some("z".repeat(32));
        m.tags = vec!["t".repeat(20); 4];
        let n = m.to_metadata_bytes().unwrap().len();
        // Note: ML-KEM-768 pubkey is ~1184 B and ML-DSA-65 sig
        // is ~3309 B — together they alone vastly exceed
        // INLINE_METADATA_MAX (512). AliasMetadata is therefore
        // **always sealed as a Blob**, not Inline. This test
        // pins that as an explicit, documented property.
        assert!(
            n > INLINE_METADATA_MAX,
            "AliasMetadata is expected to exceed the inline ceiling \
             due to embedded PQ key+sig; got {n} bytes (ceiling \
             {INLINE_METADATA_MAX}). The Blob path is the canonical \
             write path for aliases."
        );
    }

    // ── Privacy regression: no secret field names in metadata ─

    #[test]
    fn alias_metadata_excludes_kem_secret_field_names() {
        // Mirror the credential test. AliasMetadata MUST NOT
        // gain a field named `secret`, `private_key`, or
        // `kem_secret_key` — those belong on AliasBody.
        let m = fixture_metadata();
        let v = serde_json::to_value(&m).unwrap();
        let banned: std::collections::HashSet<&str> =
            ["secret", "secrets", "private_key", "kem_secret_key", "passphrase"]
                .into_iter()
                .collect();
        let keys = collect_object_keys(&v);
        for key in &keys {
            assert!(
                !banned.contains(key.to_ascii_lowercase().as_str()),
                "AliasMetadata field {key:?} matches a forbidden \
                 secret field name; move it onto AliasBody"
            );
        }
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

    // ── Indexable surface ─────────────────────────────────────

    #[test]
    fn alias_metadata_indexable_tokens_include_label_handle_namespace_tags() {
        let m = fixture_metadata();
        let toks: Vec<String> = m.tokens().into_iter().map(|c| c.into_owned()).collect();
        assert!(toks.contains(&"netflix".into()), "{toks:?}");
        assert!(toks.contains(&"inbox-demo.vito.gg".into()), "{toks:?}");
        assert!(toks.contains(&"netflix@inbox-demo.vito.gg".into()), "{toks:?}");
        assert!(toks.contains(&"Streaming".into()), "{toks:?}");
        assert!(toks.contains(&"streaming".into()), "{toks:?}");
        assert!(toks.contains(&"shared".into()), "{toks:?}");
    }

    #[test]
    fn alias_metadata_indexable_filter_keys_include_namespace_active_tags() {
        let m = fixture_metadata();
        let keys: Vec<(String, String)> = m
            .filter_keys()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect();
        assert!(keys.contains(&("namespace".into(), "inbox-demo.vito.gg".into())));
        assert!(keys.contains(&("active".into(), "true".into())));
        assert!(keys.contains(&("tag".into(), "streaming".into())));
        assert!(keys.contains(&("tag".into(), "shared".into())));
    }

    #[test]
    fn alias_metadata_build_hit_uses_label_or_falls_back_to_address() {
        let m = fixture_metadata();
        let hit = m.build_hit(RecordId([0u8; 16]));
        assert_eq!(hit.title, "Streaming");
        assert_eq!(hit.subtitle.as_deref(), Some("netflix@inbox-demo.vito.gg"));
        assert_eq!(hit.record_type, RecordType::Alias);

        let mut without_label = m.clone();
        without_label.label = None;
        let hit2 = without_label.build_hit(RecordId([0u8; 16]));
        assert_eq!(hit2.title, "netflix@inbox-demo.vito.gg");
    }

    // ── ZeroizeOnDrop probe for AliasBody ─────────────────────

    #[test]
    fn alias_body_zeroize_on_drop_clears_kem_secret() {
        // We trust MlKem768SecretKeyBytes to be ZeroizeOnDrop
        // (verified in core::crypto::keys tests). Here we
        // assert the marker is present at the AliasBody field
        // level so a future schema edit can't silently drop it.
        fn _is_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let body = fixture_body();
        _is_zeroize_on_drop(&body.alias_kem_secret_key);
    }

    // ── parse_address ─────────────────────────────────────────

    #[test]
    fn parse_address_typical() {
        let (h, n) = AliasMetadata::parse_address("netflix@inbox-demo.vito.gg").unwrap();
        assert_eq!(h, "netflix");
        assert_eq!(n, "inbox-demo.vito.gg");
    }

    #[test]
    fn parse_address_lowercases_domain_only() {
        // Local part is RFC-legal case-sensitive; we preserve
        // it. Domain is case-insensitive per DNS; we normalise.
        let (h, n) = AliasMetadata::parse_address("Foo+Tag@Inbox.Vito.GG").unwrap();
        assert_eq!(h, "Foo+Tag");
        assert_eq!(n, "inbox.vito.gg");
    }

    #[test]
    fn parse_address_rejects_missing_at() {
        let err = AliasMetadata::parse_address("no-at-symbol-here").unwrap_err();
        assert!(matches!(err, ValidationError::Other(_)));
    }

    #[test]
    fn parse_address_rejects_empty_local_or_domain() {
        assert!(AliasMetadata::parse_address("@example.com").is_err());
        assert!(AliasMetadata::parse_address("local@").is_err());
    }

    #[test]
    fn parse_address_uses_rightmost_at() {
        // RFC-legal but unusual local part containing @ (when
        // quoted). We don't enforce the quoting rules here;
        // splitting on rightmost @ keeps the contract simple.
        let (h, n) = AliasMetadata::parse_address(r#""weird@local"@example.com"#).unwrap();
        assert_eq!(h, r#""weird@local""#);
        assert_eq!(n, "example.com");
    }
}
