//! `vitonomi-cli alias disable <id>` — flip the alias's
//! `active` flag to false. Keeps the directory entry so the relay
//! can decide silent-drop vs reject.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::{RecordId, RecordType};
use vitonomi_core::types::alias::AliasMetadata;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct AliasDisableArgs<'a> {
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
    args: AliasDisableArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).context("parse alias id hex")?;
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let bytes = session
        .session
        .record_store
        .get_metadata(RecordType::Alias, id)
        .await
        .map_err(|e| anyhow!("get alias metadata: {e}"))?
        .ok_or_else(|| anyhow!("alias {} not found", id.to_hex()))?;
    let mut m = AliasMetadata::from_metadata_bytes(&bytes).context("decode alias metadata")?;
    m.active = false;
    let plaintext = RecordPlaintext {
        metadata: m.to_metadata_bytes().context("re-encode metadata")?,
        body: BodyOp::Keep,
    };
    session
        .session
        .record_store
        .put_or_replace(RecordType::Alias, id, plaintext)
        .await
        .map_err(|e| anyhow!("put alias: {e}"))?;
    tracing::info!(id = %id.to_hex(), "alias disabled");
    session.shutdown().await;
    Ok(())
}
