//! `record_session` + a populated `LibraryIndex`.
//!
//! Every credential / search command opens through this so the
//! cross-type search index is available without forcing each
//! command to call `populate` itself.

use std::path::{Path, PathBuf};

use anyhow::anyhow;

use vitonomi_core::crypto::keys::MasterSecretKeys;
use vitonomi_core::errors::{CoreError, CryptoError};
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
/// The list returned by `indexed_types` is the single source of
/// truth for "which RecordTypes contribute to universal search".
///
/// # Errors
///
/// Underlying network / crypto / decode failures. Snapshot signature
/// verification failure is surfaced with a remediation hint (see
/// [`map_populate_error`]).
pub async fn open<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    state_path: &Path,
    prompts: &mut P,
) -> anyhow::Result<LibrarySession> {
    let session = record_session::open(cfg, state_path, prompts).await?;
    let index = populate_with_friendly_errors(&session, state_path).await?;
    Ok(LibrarySession { session, index })
}

/// Variant of [`open`] that reuses already-unsealed `MasterSecretKeys`.
/// Use this when a command has already unsealed the key blob for
/// client-side signing and wants to avoid a second password prompt.
///
/// # Errors
///
/// Underlying network / crypto / decode failures.
pub async fn open_with_secrets(
    cfg: &CliConfig,
    state_path: &Path,
    secrets: &MasterSecretKeys,
) -> anyhow::Result<LibrarySession> {
    let session = record_session::open_with_secrets(cfg, state_path, secrets).await?;
    let index = populate_with_friendly_errors(&session, state_path).await?;
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

async fn populate_with_friendly_errors(
    session: &RecordSession,
    state_path: &Path,
) -> anyhow::Result<LibraryIndex> {
    match LibraryIndex::populate(&session.record_store, indexed_types()).await {
        Ok(idx) => Ok(idx),
        Err(e) => Err(map_populate_error(e, state_path)),
    }
}

/// Rewrite the opaque `CryptoError::SignatureInvalid` (the most
/// common confusing failure on `populate`) with an actionable
/// remediation hint. All other errors fall through unchanged.
fn map_populate_error(err: CoreError, state_path: &Path) -> anyhow::Error {
    let heads_dir = state_dir_of(state_path).join("heads");
    if matches!(err, CoreError::Crypto(CryptoError::SignatureInvalid)) {
        return anyhow!(
            "snapshot signature verification failed — the local snapshot \
             chain at {} doesn't match the current identity. This usually \
             means `cluster create` was rerun without wiping the previous \
             chain (or `cluster restore` brought a different identity onto \
             the same state dir). Remediation: run `vitonomi-cli logout` \
             to clear local state, or remove {} and re-bootstrap.",
            heads_dir.display(),
            heads_dir.display(),
        );
    }
    anyhow!("populate LibraryIndex: {err}")
}

fn state_dir_of(state_path: &Path) -> PathBuf {
    state_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
