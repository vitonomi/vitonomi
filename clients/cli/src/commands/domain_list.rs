//! `vitonomi-cli domain list` — list the user's custom domains.

use std::path::Path;

use anyhow::anyhow;

use crate::config::CliConfig;
use crate::hub_client;
use crate::state;

pub struct DomainListArgs<'a> {
    pub state_path: &'a Path,
}

/// Run.
///
/// # Errors
///
/// Network / state failures.
#[allow(clippy::print_stdout)]
pub async fn run(cfg: &CliConfig, args: DomainListArgs<'_>) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let client = hub_client::default_client()?;
    let resp = hub_client::list_custom_domains(&client, &cfg.hub.url, &token.0).await?;
    if resp.domains.is_empty() {
        eprintln!("(no custom domains)");
        return Ok(());
    }
    for d in &resp.domains {
        println!(
            "{}\t{:?}\tverified_at_ms={}",
            d.domain,
            d.status,
            d.verified_at_ms
                .map_or_else(|| "-".to_string(), |t| t.to_string())
        );
    }
    Ok(())
}
