//! `vitonomi-cli domain verify <domain>` — trigger DNS
//! verification. Hub re-resolves and flips status to `Verified` if
//! TXT + MX records match.

use std::path::Path;

use anyhow::anyhow;

use crate::config::CliConfig;
use crate::hub_client;
use crate::state;

pub struct DomainVerifyArgs<'a> {
    pub state_path: &'a Path,
    pub domain: String,
}

/// Run.
///
/// # Errors
///
/// Network / state failures.
pub async fn run(cfg: &CliConfig, args: DomainVerifyArgs<'_>) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let client = hub_client::default_client()?;
    let v = hub_client::verify_custom_domain(&client, &cfg.hub.url, &token.0, &args.domain).await?;
    tracing::info!(domain = %v.domain, verified_at_ms = v.verified_at_ms, "domain verified");
    Ok(())
}
