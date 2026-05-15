//! `record_session` + a populated `LibraryIndex`.
//!
//! Every credential / search command opens through this so the
//! cross-type search index is available without forcing each
//! command to call `populate` itself.

use std::path::Path;

use anyhow::Context as _;

use vitonomi_core::record::RecordType;
use vitonomi_core::search::LibraryIndex;

use crate::commands::record_session::{self, RecordSession};
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct LibrarySession {
    pub session: RecordSession,
    pub index: LibraryIndex,
}

impl LibrarySession {
    /// Drop the session cleanly. The index is dropped along with
    /// the surrounding struct.
    pub async fn shutdown(self) {
        self.session.shutdown().await;
    }
}

/// Open a record session and build a `LibraryIndex` over every
/// RecordType currently wired into the search registry.
///
/// In Phase 6 only `Credential` is wired (Phase 7 adds `Alias` /
/// `AliasMessage`). The list here is the single source of truth
/// for "which types contribute to universal search".
///
/// # Errors
///
/// Underlying network / crypto / decode failures.
pub async fn open<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    state_path: &Path,
    prompts: &mut P,
) -> anyhow::Result<LibrarySession> {
    let session = record_session::open(cfg, state_path, prompts).await?;
    let index = LibraryIndex::populate(&session.record_store, indexed_types())
        .await
        .context("populate LibraryIndex")?;
    Ok(LibrarySession { session, index })
}

/// RecordTypes that contribute to the cross-type search index.
#[must_use]
pub const fn indexed_types() -> &'static [RecordType] {
    &[
        RecordType::Credential,
        RecordType::Alias,
        RecordType::AliasMessage,
        RecordType::Domain,
    ]
}
