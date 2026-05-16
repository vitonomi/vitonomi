//! `vitonomi-cli subdomain release <name> --domain <base>` —
//! release a previously-claimed subdomain. Hub tombstones aliases
//! under the subdomain, and the CLI tombstones the matching local
//! `Domain` record so `subdomain list` and the `alias create`
//! namespace-ownership check both see the release immediately.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::RecordType;
use vitonomi_core::types::domain::DomainMetadata;
use vitonomi_core::types::subdomain::Subdomain;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
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
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: SubdomainReleaseArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let sub = Subdomain::parse(&args.subdomain).context("invalid subdomain")?;
    let client = hub_client::default_client()?;
    hub_client::release_subdomain(&client, &cfg.hub.url, &token.0, &args.base_domain, &sub).await?;

    // Tombstone the matching local Domain record. Same deterministic
    // id as `subdomain claim` wrote.
    let full_domain = format!("{}.{}", sub.as_str(), args.base_domain);
    let record_id = DomainMetadata::record_id_for(&full_domain);
    let lib = library_session::open(cfg, args.state_path, prompts).await?;
    let res = lib
        .session
        .record_store
        .delete(RecordType::Domain, record_id)
        .await;
    lib.shutdown().await;
    res.map_err(|e| anyhow!("tombstone local Domain record: {e}"))?;

    tracing::info!(
        subdomain = %sub,
        base = %args.base_domain,
        domain = %full_domain,
        "subdomain released"
    );
    Ok(())
}
