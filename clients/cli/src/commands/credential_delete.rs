//! `vitonomi-cli credential delete <id>`

use std::path::Path;

use anyhow::anyhow;

use vitonomi_core::record::{RecordId, RecordType};

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialDeleteArgs<'a> {
    pub state_path: &'a Path,
    pub id_hex: String,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialDeleteArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).map_err(|e| anyhow!("invalid record id: {e}"))?;
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    session
        .session
        .record_store
        .delete(RecordType::Credential, id)
        .await
        .map_err(|e| anyhow!("delete: {e}"))?;
    eprintln!("deleted {id}");
    session.shutdown().await;
    Ok(())
}
