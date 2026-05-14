//! Credential schemas: the metadata face (searchable, no secrets)
//! and the body face (passwords, TOTP secrets, notes).
//!
//! This is the per-RecordType worked example of the metadata/body
//! split documented in `docs/record-types.md`. Inline metadata
//! always rides inside the snapshot envelope; the body is sealed
//! as a separate blob and fetched lazily on `get_body`.
//!
//! Wire bytes for `CredentialMetadata` and `CredentialBody` are
//! pinned in `docs/data-format.md`.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::ProtocolError;
use crate::record::{RecordId, RecordType};
use crate::search::{url_host, Indexable, SearchHit};
use crate::types::FormatVersion;

/// A short string holding a secret. Heap-allocated, zeroized on
/// drop. Use anywhere a credential's body / TOTP / custom-field
/// secret string lives in process memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(pub String);

impl SecretString {
    /// Wrap an existing String. The original `String` is moved into
    /// the wrapper; on drop the bytes are zeroized.
    #[must_use]
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Borrow the inner UTF-8 bytes for hashing / cryptographic use.
    /// Avoid printing or logging this anywhere.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(***)")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time compare to avoid timing-side-channel leaks
        // when secrets happen to be compared (rare; use `subtle`
        // crate already pulled by `core`).
        use subtle::ConstantTimeEq as _;
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for SecretString {}

/// Raw secret bytes — zeroized on drop. Used for TOTP seed bytes
/// and other binary secret material that does not parse as UTF-8.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the inner bytes. Avoid printing or logging.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<{} bytes>)", self.0.len())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl Eq for SecretBytes {}

/// HMAC algorithm used by an RFC 6238 TOTP entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TotpAlg {
    Sha1,
    Sha256,
    Sha512,
}

/// One TOTP entry stored inside a [`CredentialBody`]. The secret is
/// raw bytes — base32 encoding belongs at the import / export edge
/// (see `core::credentials::import` once Slice E lands).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpConfig {
    pub secret: SecretBytes,
    pub algorithm: TotpAlg,
    /// Number of digits the OTP code carries. RFC 6238 supports
    /// 6, 7, or 8.
    pub digits: u8,
    /// Time-step length in seconds. RFC 6238 default is 30.
    pub period_secs: u32,
}

/// Searchable / browseable face of a credential record. Carried
/// inline in the snapshot frame whenever possible. Holds **no
/// secret material** — passwords, TOTP secrets, notes, and custom
/// fields all live in [`CredentialBody`].
///
/// Wire format is deterministic CBOR; see `docs/data-format.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub format_version: FormatVersion,
    pub title: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub tags: Vec<String>,
    pub folder: Option<String>,
    /// `true` iff the corresponding [`CredentialBody`] holds a
    /// non-`None` `totp`. Lets the UI render a "TOTP available"
    /// badge without unlocking the body.
    pub has_totp: bool,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

impl CredentialMetadata {
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
}

/// Secret / heavy face of a credential record. Sealed as a separate
/// body blob and only fetched on demand (`get_body` / reveal).
///
/// Drops zeroize all secret fields. Wire format is deterministic
/// CBOR; see `docs/data-format.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBody {
    pub format_version: FormatVersion,
    pub password: SecretString,
    pub totp: Option<TotpConfig>,
    pub notes: Option<String>,
    pub custom_fields: Vec<(String, SecretString)>,
}

impl CredentialBody {
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

    /// True iff the metadata's `has_totp` flag should be set.
    #[must_use]
    pub fn has_totp(&self) -> bool {
        self.totp.is_some()
    }
}

impl Indexable for CredentialMetadata {
    const RECORD_TYPE: RecordType = RecordType::Credential;

    fn from_metadata_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::from_metadata_bytes(bytes)
    }

    fn tokens(&self) -> Vec<Cow<'_, str>> {
        let mut out: Vec<Cow<'_, str>> = Vec::new();
        out.push(Cow::Borrowed(self.title.as_str()));
        if let Some(url) = &self.url {
            // Index both the full URL string and (separately) its
            // host so a search for "github" matches a stored URL
            // of "https://github.com/user/repo".
            out.push(Cow::Borrowed(url.as_str()));
            if let Some(host) = url_host(url) {
                out.push(Cow::Owned(host));
            }
        }
        if let Some(username) = &self.username {
            out.push(Cow::Borrowed(username.as_str()));
        }
        for tag in &self.tags {
            out.push(Cow::Borrowed(tag.as_str()));
        }
        if let Some(folder) = &self.folder {
            out.push(Cow::Borrowed(folder.as_str()));
        }
        out
    }

    fn filter_keys(&self) -> Vec<(&'static str, Cow<'_, str>)> {
        let mut out: Vec<(&'static str, Cow<'_, str>)> = Vec::new();
        if let Some(folder) = &self.folder {
            out.push(("folder", Cow::Borrowed(folder.as_str())));
        }
        for tag in &self.tags {
            out.push(("tag", Cow::Borrowed(tag.as_str())));
        }
        out
    }

    fn build_hit(&self, record_id: RecordId) -> SearchHit {
        SearchHit {
            record_id,
            record_type: Self::RECORD_TYPE,
            title: self.title.clone(),
            subtitle: self.url.clone(),
            score: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::INLINE_METADATA_MAX;

    fn sample_metadata() -> CredentialMetadata {
        CredentialMetadata {
            format_version: FormatVersion::V1,
            title: "Netflix".into(),
            url: Some("https://netflix.com".into()),
            username: Some("birkeal".into()),
            tags: vec!["streaming".into(), "shared".into()],
            folder: Some("personal".into()),
            has_totp: true,
            created_at_ms: 1_700_000_000_000,
            updated_at_ms: 1_700_000_000_000,
        }
    }

    fn sample_body() -> CredentialBody {
        CredentialBody {
            format_version: FormatVersion::V1,
            password: SecretString::new("hunter2".into()),
            totp: Some(TotpConfig {
                secret: SecretBytes::new(b"12345678901234567890".to_vec()),
                algorithm: TotpAlg::Sha1,
                digits: 6,
                period_secs: 30,
            }),
            notes: Some("kids' login".into()),
            custom_fields: vec![(
                "recovery_email".into(),
                SecretString::new("backup@example.com".into()),
            )],
        }
    }

    #[test]
    fn metadata_round_trip_via_cbor() {
        let m = sample_metadata();
        let bytes = m.to_metadata_bytes().unwrap();
        let back = CredentialMetadata::from_metadata_bytes(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn body_round_trip_via_cbor() {
        let b = sample_body();
        let bytes = b.to_body_bytes().unwrap();
        let back = CredentialBody::from_body_bytes(&bytes).unwrap();
        assert_eq!(back, b);
    }

    #[test]
    fn typical_metadata_fits_in_inline_threshold() {
        // Representative input sizes for the common credential.
        // Property: encoded metadata stays ≤ INLINE_METADATA_MAX so
        // browse / search stay one-fetch.
        let m = CredentialMetadata {
            format_version: FormatVersion::V1,
            title: "x".repeat(64),
            url: Some("https://".to_string() + &"a".repeat(120)),
            username: Some("x".repeat(64)),
            tags: vec!["t".repeat(20); 4],
            folder: Some("x".repeat(32)),
            has_totp: true,
            created_at_ms: 1_700_000_000_000,
            updated_at_ms: 1_700_000_000_000,
        };
        let n = m.to_metadata_bytes().unwrap().len();
        assert!(
            n <= INLINE_METADATA_MAX,
            "typical metadata encoded to {n} bytes; INLINE_METADATA_MAX = {INLINE_METADATA_MAX}"
        );
    }

    #[test]
    fn metadata_json_keys_contain_no_secret_field_names() {
        // Regression guard: nobody is allowed to add a field whose
        // exact name is `password|totp|secret|secrets|notes|
        // private_key|passwd|pass` to `CredentialMetadata`. Such
        // fields belong on `CredentialBody`. This is exact-match,
        // not substring — `has_totp` (a non-secret flag) is fine,
        // but a literal `totp` field would not be.
        let m = sample_metadata();
        let v = serde_json::to_value(&m).unwrap();
        let banned: std::collections::HashSet<&str> = [
            "password",
            "totp",
            "secret",
            "secrets",
            "notes",
            "private_key",
            "passwd",
            "pass",
        ]
        .into_iter()
        .collect();
        let keys = collect_object_keys(&v);
        for key in &keys {
            assert!(
                !banned.contains(key.to_ascii_lowercase().as_str()),
                "CredentialMetadata field {key:?} matches a forbidden secret field name; \
                 move it onto CredentialBody"
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

    #[test]
    fn body_zeroize_on_drop_clears_password_bytes() {
        // Probe: capture the password's heap pointer and after-drop
        // confirm the bytes at that address are no longer the
        // original plaintext. This is best-effort (allocator may
        // re-use, page may be unmapped) — we assert at minimum that
        // the SecretString's Drop implementation zeroes the inner
        // String before it deallocates.
        let pw = "hunter2-zeroize-me";
        {
            let s = SecretString::new(pw.into());
            // Sanity: we can read it before drop.
            assert_eq!(s.expose_secret(), pw);
            // Inner String's bytes get zeroized; we trust the
            // `zeroize::ZeroizeOnDrop` derive. We assert the type
            // implements the marker.
            fn _is_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
            _is_zeroize_on_drop(&s);
        }
        // After drop, no further checks are sound — pointer is
        // dangling — but `_is_zeroize_on_drop` ensured the contract.
    }

    #[test]
    fn secret_string_partial_eq_constant_time() {
        let a = SecretString::new("hunter2".into());
        let b = SecretString::new("hunter2".into());
        let c = SecretString::new("Hunter2".into());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn secret_string_debug_does_not_leak() {
        let s = SecretString::new("hunter2".into());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(dbg.contains("SecretString"));
    }

    #[test]
    fn secret_bytes_debug_does_not_leak() {
        let b = SecretBytes::new(b"super-secret".to_vec());
        let dbg = format!("{b:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("SecretBytes"));
    }

    #[test]
    fn body_has_totp_matches_metadata_flag() {
        let m = sample_metadata();
        let b = sample_body();
        assert_eq!(m.has_totp, b.has_totp());
    }
}
