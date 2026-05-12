//! `vitonomi-cli record delete <type> <id>` — append a tombstone
//! frame for `id`. Idempotent: deleting a record that's already gone
//! is a no-op success.

use std::path::Path;

use anyhow::anyhow;

use vitonomi_core::record::{RecordId, RecordType};

use crate::commands::record_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct RecordDeleteArgs<'a> {
    pub state_path: &'a Path,
    pub record_type: RecordType,
    pub id_hex: String,
}

/// Tombstone a record.
///
/// # Errors
///
/// I/O / network / crypto failures.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: RecordDeleteArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).map_err(|e| anyhow!("invalid RecordId hex: {e}"))?;
    let session = record_session::open(cfg, args.state_path, prompts).await?;
    session
        .record_store
        .delete(args.record_type, id)
        .await
        .map_err(|e| anyhow!("delete record: {e}"))?;
    eprintln!("deleted {id}");
    session.shutdown().await;
    Ok(())
}
