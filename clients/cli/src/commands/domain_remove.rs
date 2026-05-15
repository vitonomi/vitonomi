//! `vitonomi-cli domain remove <domain>` — remove a custom domain.
//! Hub tombstones aliases under the domain.

use std::path::Path;

use anyhow::anyhow;

use crate::config::CliConfig;
use crate::hub_client;
use crate::state;

pub struct DomainRemoveArgs<'a> {
    pub state_path: &'a Path,
    pub domain: String,
}

/// Run.
///
/// # Errors
///
/// Network / state failures.
pub async fn run(cfg: &CliConfig, args: DomainRemoveArgs<'_>) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let client = hub_client::default_client()?;
    hub_client::remove_custom_domain(&client, &cfg.hub.url, &token.0, &args.domain).await?;
    tracing::info!(domain = %args.domain, "custom domain removed");
    Ok(())
}
