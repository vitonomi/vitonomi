//! `vitonomi-cli subdomain release <name> --domain <base>` —
//! release a previously-claimed subdomain. Hub tombstones aliases
//! under the subdomain.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::types::subdomain::Subdomain;

use crate::config::CliConfig;
use crate::hub_client;
use crate::state;

pub struct SubdomainReleaseArgs<'a> {
    pub state_path: &'a Path,
    pub subdomain: String,
    pub base_domain: String,
}

/// Run subdomain release.
///
/// # Errors
///
/// Validation, network, or state failures.
pub async fn run(cfg: &CliConfig, args: SubdomainReleaseArgs<'_>) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let sub = Subdomain::parse(&args.subdomain).context("invalid subdomain")?;
    let client = hub_client::default_client()?;
    hub_client::release_subdomain(&client, &cfg.hub.url, &token.0, &args.base_domain, &sub).await?;
    tracing::info!(subdomain = %sub, base = %args.base_domain, "subdomain released");
    Ok(())
}
