//! `vitonomi-cli alias delete <id>` — tombstone an alias and
//! revoke its directory entry on the hub.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::{RecordId, RecordType};
use vitonomi_core::types::alias::AliasMetadata;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state;

pub struct AliasDeleteArgs<'a> {
    pub state_path: &'a Path,
    pub id_hex: String,
}

/// Run.
///
/// # Errors
///
/// Crypto / network / state failures.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: AliasDeleteArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).context("parse alias id hex")?;
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let meta_bytes = session
        .session
        .record_store
        .get_metadata(RecordType::Alias, id)
        .await
        .map_err(|e| anyhow!("get alias metadata: {e}"))?
        .ok_or_else(|| anyhow!("alias {} not found", id.to_hex()))?;
    let m = AliasMetadata::from_metadata_bytes(&meta_bytes).context("decode alias metadata")?;

    // Revoke the directory entry first so the relay stops accepting
    // mail; then tombstone the local record.
    let client = hub_client::default_client()?;
    hub_client::revoke_alias_pubkey(&client, &cfg.hub.url, &token.0, &m.alias_handle, &m.namespace)
        .await?;
    session
        .session
        .record_store
        .delete(RecordType::Alias, id)
        .await
        .map_err(|e| anyhow!("delete alias record: {e}"))?;
    tracing::info!(id = %id.to_hex(), address = %m.full_address(), "alias deleted");
    session.shutdown().await;
    Ok(())
}
