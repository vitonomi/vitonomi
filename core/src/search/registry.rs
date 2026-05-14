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
use crate::types::credential::CredentialMetadata;

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
        RecordType::Alias | RecordType::AliasMessage => Err(ProtocolError::Malformed(format!(
            "indexing for RecordType::{rt:?} is not implemented yet (Phase 7)"
        ))),
    }
}
