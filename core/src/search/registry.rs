//! Centralised RecordType → metadata-decoder dispatch for the
//! search subsystem.
//!
//! The `match` on [`RecordType`] is exhaustive over the closed
//! enum. Adding a new RecordType means adding one match arm here
//! at the same time as bumping `RecordType::from_u8`. Phase 6
//! wires only `Credential`; `Alias` / `AliasMessage` arms return
//! a typed error explaining they're not implemented yet — Phase 7
//! fills them in.

use crate::errors::ProtocolError;
use crate::record::{RecordId, RecordType};
use crate::search::{Indexable, IndexedDoc};
use crate::types::alias::AliasMetadata;
use crate::types::alias_message::AliasMessageMetadata;
use crate::types::credential::CredentialMetadata;
use crate::types::domain::DomainMetadata;

/// Decode `metadata_bytes` according to `rt`'s schema, derive
/// search tokens / filter keys / display hit, and return them
/// as an [`IndexedDoc`] ready for insertion into a
/// [`crate::search::LibraryIndex`].
///
/// # Errors
///
/// `ProtocolError::Malformed` for record types that have no
/// indexer wired yet (Phase 7 adds `Alias` / `AliasMessage`).
/// Otherwise any decode error from the per-type implementation.
pub fn index_metadata(
    rt: RecordType,
    record_id: RecordId,
    metadata_bytes: &[u8],
) -> Result<IndexedDoc, ProtocolError> {
    match rt {
        RecordType::Credential => {
            let m = <CredentialMetadata as Indexable>::from_metadata_bytes(metadata_bytes)?;
            Ok(IndexedDoc {
                tokens: m.tokens().into_iter().map(|c| c.into_owned()).collect(),
                filter_keys: m
                    .filter_keys()
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.into_owned()))
                    .collect(),
                hit: m.build_hit(record_id),
            })
        }
        RecordType::Alias => {
            let m = <AliasMetadata as Indexable>::from_metadata_bytes(metadata_bytes)?;
            Ok(IndexedDoc {
                tokens: m.tokens().into_iter().map(|c| c.into_owned()).collect(),
                filter_keys: m
                    .filter_keys()
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.into_owned()))
                    .collect(),
                hit: m.build_hit(record_id),
            })
        }
        RecordType::AliasMessage => {
            let m = <AliasMessageMetadata as Indexable>::from_metadata_bytes(metadata_bytes)?;
            Ok(IndexedDoc {
                tokens: m.tokens().into_iter().map(|c| c.into_owned()).collect(),
                filter_keys: m
                    .filter_keys()
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.into_owned()))
                    .collect(),
                hit: m.build_hit(record_id),
            })
        }
        RecordType::Domain => {
            let m = <DomainMetadata as Indexable>::from_metadata_bytes(metadata_bytes)?;
            Ok(IndexedDoc {
                tokens: m.tokens().into_iter().map(|c| c.into_owned()).collect(),
                filter_keys: m
                    .filter_keys()
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.into_owned()))
                    .collect(),
                hit: m.build_hit(record_id),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::{ml_dsa_65_keypair, ml_dsa_65_sign, ml_kem_768_keypair};
    use crate::types::alias::{AliasMetadata, SpamPolicy};
    use crate::types::FormatVersion;

    #[test]
    fn index_metadata_decodes_alias_metadata() {
        let kem = ml_kem_768_keypair().unwrap();
        let dsa = ml_dsa_65_keypair().unwrap();
        let sig = ml_dsa_65_sign(&dsa.secret, &kem.public.0).unwrap();
        let m = AliasMetadata {
            format_version: FormatVersion::V1,
            alias_id_hint: [3u8; 16],
            alias_handle: "support".into(),
            namespace: "inbox-demo.vito.gg".into(),
            label: Some("Tickets".into()),
            alias_kem_pubkey: kem.public,
            sig_user_over_pubkey: sig,
            expiry_ms: None,
            active: true,
            spam_policy: SpamPolicy::OpenInbox,
            tags: vec!["work".into()],
            last_used_at_ms: None,
            created_at_ms: 0,
        };
        let bytes = m.to_metadata_bytes().unwrap();
        let doc = index_metadata(RecordType::Alias, RecordId([9u8; 16]), &bytes).unwrap();
        assert!(doc.tokens.iter().any(|t| t == "support"));
        assert!(doc
            .tokens
            .iter()
            .any(|t| t == "support@inbox-demo.vito.gg"));
        assert_eq!(doc.hit.title, "Tickets");
        assert_eq!(doc.hit.record_type, RecordType::Alias);
    }

    #[test]
    fn index_metadata_decodes_alias_message() {
        use crate::types::alias_message::{AliasMessageMetadata, ValidationOutcome};
        let m = AliasMessageMetadata {
            format_version: FormatVersion::V1,
            alias_id: RecordId([3u8; 16]),
            sender: "alice@example.com".into(),
            subject: "Welcome to vitonomi".into(),
            received_at_ms: 0,
            size_bytes: 0,
            snippet: "hello world".into(),
            has_attachments: false,
            attachment_count: 0,
            spf: ValidationOutcome::Pass,
            dkim: ValidationOutcome::Pass,
            dmarc: ValidationOutcome::Pass,
        };
        let bytes = m.to_metadata_bytes().unwrap();
        let doc = index_metadata(RecordType::AliasMessage, RecordId([0u8; 16]), &bytes).unwrap();
        assert!(doc.tokens.iter().any(|t| t.contains("alice")));
        assert!(doc.tokens.iter().any(|t| t == "Welcome to vitonomi"));
        assert_eq!(doc.hit.title, "Welcome to vitonomi");
        assert_eq!(doc.hit.subtitle.as_deref(), Some("alice@example.com"));
        assert_eq!(doc.hit.record_type, RecordType::AliasMessage);
    }
}
