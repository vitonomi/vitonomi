//! `vitonomi-cli domain remove <domain>` — remove a custom domain.
//! Hub tombstones aliases under the domain, and the CLI tombstones
//! the matching local `Domain` record so `domain list` and
//! `alias create` reflect the removal immediately.

use std::path::Path;

use anyhow::anyhow;

use vitonomi_core::record::RecordType;
use vitonomi_core::types::domain::DomainMetadata;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state;

pub struct DomainRemoveArgs<'a> {
    pub state_path: &'a Path,
    pub domain: String,
}

/// Run.
///
/// # Errors
///
/// Network / state / record-store failures.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: DomainRemoveArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let client = hub_client::default_client()?;
    hub_client::remove_domain(&client, &cfg.hub.url, &token.0, &args.domain).await?;

    let record_id = DomainMetadata::record_id_for(&args.domain);
    let lib = library_session::open(cfg, args.state_path, prompts).await?;
    let res = lib
        .session
        .record_store
        .delete(RecordType::Domain, record_id)
        .await;
    lib.shutdown().await;
    res.map_err(|e| anyhow!("tombstone local Domain record: {e}"))?;

    tracing::info!(domain = %args.domain, "custom domain removed");
    Ok(())
}
