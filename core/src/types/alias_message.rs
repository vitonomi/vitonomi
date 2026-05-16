//! Alias-message schema — one inbound mail received via an
//! alias.
//!
//! The body face IS the message content (headers + body +
//! attachments), AEAD-then-self-encrypted; the RecordFrame's
//! `body_data_map` references the resulting chunks. There is
//! no `AliasMessageBody` struct — that field on the frame is
//! the body.
//!
//! Metadata is the searchable / browseable face: sender,
//! subject, snippet, validation outcomes. Inline in the
//! snapshot so an inbox listing renders without decrypting any
//! message body.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::ProtocolError;
use crate::record::{RecordId, RecordType};
use crate::search::{Indexable, SearchHit};
use crate::types::FormatVersion;

/// SPF / DKIM / DMARC outcome for an inbound message. Captured
/// once at the mx relay's RCPT / DATA boundary and stored on the
/// metadata so the user can filter / display without trusting
/// the mx relay to repeat the validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationOutcome {
    Pass,
    Fail,
    None,
}

/// Searchable / browseable face of an inbound mail. Inline in
/// the snapshot frame; lets the inbox UI render sender +
/// subject + snippet without decrypting the message body.
///
/// Field-size discipline: `snippet` capped to 140 chars,
/// `sender` capped to 320 chars (the RFC 5321 max). The body
/// face (the encrypted MIME bytes) lives in the frame's
/// `body_data_map` — there is no separate body struct in this
/// module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasMessageMetadata {
    pub format_version: FormatVersion,
    /// The alias this message arrived at. Foreign-key to the
    /// `Alias` record's id.
    pub alias_id: RecordId,
    /// RFC 5321 envelope sender (MAIL FROM). Capped to 320.
    pub sender: String,
    /// Decoded `Subject:` header. May be empty.
    pub subject: String,
    /// Server-side receive timestamp (mx relay's clock at the
    /// moment DATA finished).
    pub received_at_ms: u64,
    /// Total size of the encrypted message body in bytes.
    pub size_bytes: u64,
    /// First few characters of the plaintext body, capped to
    /// 140 chars by the mx relay so the inbox UI can show a
    /// preview without decrypting. The mx relay computes the
    /// snippet from the plaintext while it's still in RAM and
    /// drops the rest.
    pub snippet: String,
    pub has_attachments: bool,
    pub attachment_count: u16,
    pub spf: ValidationOutcome,
    pub dkim: ValidationOutcome,
    pub dmarc: ValidationOutcome,
}

impl AliasMessageMetadata {
    /// Encode to deterministic CBOR for `MetadataField::Inline`
    /// storage on the snapshot frame.
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

impl Indexable for AliasMessageMetadata {
    const RECORD_TYPE: RecordType = RecordType::AliasMessage;

    fn from_metadata_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::from_metadata_bytes(bytes)
    }

    fn tokens(&self) -> Vec<Cow<'_, str>> {
        vec![
            Cow::Borrowed(self.sender.as_str()),
            Cow::Borrowed(self.subject.as_str()),
            Cow::Borrowed(self.snippet.as_str()),
        ]
    }

    fn filter_keys(&self) -> Vec<(&'static str, Cow<'_, str>)> {
        let mut out: Vec<(&'static str, Cow<'_, str>)> = Vec::new();
        out.push((
            "has_attachments",
            Cow::Borrowed(if self.has_attachments { "true" } else { "false" }),
        ));
        out.push(("spf", Cow::Borrowed(self.spf.as_str())));
        out.push(("dkim", Cow::Borrowed(self.dkim.as_str())));
        out.push(("dmarc", Cow::Borrowed(self.dmarc.as_str())));
        out
    }

    fn build_hit(&self, record_id: RecordId) -> SearchHit {
        SearchHit {
            record_id,
            record_type: Self::RECORD_TYPE,
            title: if self.subject.is_empty() {
                "(no subject)".to_string()
            } else {
                self.subject.clone()
            },
            subtitle: Some(self.sender.clone()),
            score: 0.0,
        }
    }
}

impl ValidationOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::None => "none",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::INLINE_METADATA_MAX;

    fn fixture() -> AliasMessageMetadata {
        AliasMessageMetadata {
            format_version: FormatVersion::V1,
            alias_id: RecordId([7u8; 16]),
            sender: "alice@example.com".into(),
            subject: "Welcome to vitonomi".into(),
            received_at_ms: 1_700_000_000_000,
            size_bytes: 4096,
            snippet: "Thanks for signing up — your inbox is ready.".into(),
            has_attachments: false,
            attachment_count: 0,
            spf: ValidationOutcome::Pass,
            dkim: ValidationOutcome::Pass,
            dmarc: ValidationOutcome::Pass,
        }
    }

    #[test]
    fn alias_message_metadata_round_trip() {
        let m = fixture();
        let bytes = m.to_metadata_bytes().unwrap();
        let back = AliasMessageMetadata::from_metadata_bytes(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn alias_message_metadata_typical_size_fits_inline_threshold() {
        // Representative (not pathological) inbox row: 50-char
        // sender, 80-char subject, 140-char snippet, no
        // attachments. This is what most inbound mails encode
        // to and what determines whether the inbox listing
        // stays one-fetch.
        let m = AliasMessageMetadata {
            format_version: FormatVersion::V1,
            alias_id: RecordId([0u8; 16]),
            sender: "a".repeat(50),
            subject: "s".repeat(80),
            received_at_ms: 0,
            size_bytes: 0,
            snippet: "p".repeat(140),
            has_attachments: false,
            attachment_count: 0,
            spf: ValidationOutcome::Pass,
            dkim: ValidationOutcome::Pass,
            dmarc: ValidationOutcome::Pass,
        };
        let n = m.to_metadata_bytes().unwrap().len();
        assert!(
            n <= INLINE_METADATA_MAX,
            "typical AliasMessageMetadata encoded to {n} bytes; \
             INLINE_METADATA_MAX = {INLINE_METADATA_MAX}. The 95th-\
             percentile inbox row must stay one-fetch."
        );
    }

    #[test]
    fn alias_message_metadata_pathological_size_falls_back_to_blob() {
        // Worst-case realistic size: 320-char sender (RFC 5321
        // max), 256-char subject, 140-char snippet. This DOES
        // exceed INLINE_METADATA_MAX, which means the snapshot
        // writer will seal it as a `MetadataField::Blob` and
        // the inbox listing pays one extra chunk fetch for
        // these specific records — acceptable since they're
        // rare. Pinning the property keeps the tradeoff
        // explicit so a future schema edit can't silently shift
        // every row to Blob.
        let m = AliasMessageMetadata {
            format_version: FormatVersion::V1,
            alias_id: RecordId([0u8; 16]),
            sender: "a".repeat(320),
            subject: "s".repeat(256),
            received_at_ms: 0,
            size_bytes: 0,
            snippet: "p".repeat(140),
            has_attachments: true,
            attachment_count: 7,
            spf: ValidationOutcome::Pass,
            dkim: ValidationOutcome::Pass,
            dmarc: ValidationOutcome::Pass,
        };
        let n = m.to_metadata_bytes().unwrap().len();
        assert!(
            n > INLINE_METADATA_MAX,
            "pathological AliasMessageMetadata at {n} bytes; if this \
             ever fits inline (INLINE_METADATA_MAX = \
             {INLINE_METADATA_MAX}), the typical-size invariant \
             above can be tightened."
        );
    }

    #[test]
    fn alias_message_metadata_indexable_tokens_include_sender_subject_snippet() {
        let m = fixture();
        let toks: Vec<String> = m.tokens().into_iter().map(|c| c.into_owned()).collect();
        assert!(toks.contains(&"alice@example.com".into()));
        assert!(toks.contains(&"Welcome to vitonomi".into()));
        assert!(toks
            .iter()
            .any(|t| t.contains("Thanks for signing up")));
    }

    #[test]
    fn alias_message_build_hit_falls_back_when_subject_empty() {
        let mut m = fixture();
        m.subject.clear();
        let hit = m.build_hit(RecordId([0u8; 16]));
        assert_eq!(hit.title, "(no subject)");
        assert_eq!(hit.subtitle.as_deref(), Some("alice@example.com"));
        assert_eq!(hit.record_type, RecordType::AliasMessage);
    }

    #[test]
    fn alias_message_filter_keys_carry_validation_outcomes() {
        let m = fixture();
        let keys: Vec<(String, String)> = m
            .filter_keys()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect();
        assert!(keys.contains(&("has_attachments".into(), "false".into())));
        assert!(keys.contains(&("spf".into(), "pass".into())));
        assert!(keys.contains(&("dkim".into(), "pass".into())));
        assert!(keys.contains(&("dmarc".into(), "pass".into())));
    }

    #[test]
    fn validation_outcome_round_trips_via_serde() {
        for v in [
            ValidationOutcome::Pass,
            ValidationOutcome::Fail,
            ValidationOutcome::None,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: ValidationOutcome = serde_json::from_str(&s).unwrap();
            assert_eq!(back, v);
        }
    }
}
