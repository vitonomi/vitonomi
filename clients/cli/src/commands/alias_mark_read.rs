//! `vitonomi-cli alias mark-read <alias-id> <message-id>` —
//! placeholder: per-message "read" state lives on a future client-
//! local index (Phase 11+). For now this prints the IDs so scripts
//! can chain it as a no-op marker.

use std::path::Path;

use anyhow::Context as _;

use vitonomi_core::record::RecordId;

use crate::config::CliConfig;

pub struct AliasMarkReadArgs<'a> {
    pub state_path: &'a Path,
    pub alias_id_hex: String,
    pub message_id_hex: String,
}

/// Run.
///
/// # Errors
///
/// Hex parse failures.
pub async fn run(_cfg: &CliConfig, args: AliasMarkReadArgs<'_>) -> anyhow::Result<()> {
    let alias_id = RecordId::from_hex(&args.alias_id_hex).context("parse alias id hex")?;
    let msg_id = RecordId::from_hex(&args.message_id_hex).context("parse message id hex")?;
    let _ = args.state_path;
    tracing::info!(
        alias = %alias_id.to_hex(),
        msg = %msg_id.to_hex(),
        "alias message marked read (no-op until per-message state lands)"
    );
    Ok(())
}
