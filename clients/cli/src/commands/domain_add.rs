//! `vitonomi-cli domain add <domain>` — register a custom domain
//! with the hub. Hub returns the TXT + MX records to publish at
//! the user's DNS provider.

use std::path::Path;

use anyhow::anyhow;

use crate::config::CliConfig;
use crate::hub_client;
use crate::state;

pub struct DomainAddArgs<'a> {
    pub state_path: &'a Path,
    pub domain: String,
}

/// Run.
///
/// # Errors
///
/// Network / state failures.
#[allow(clippy::print_stdout)]
pub async fn run(cfg: &CliConfig, args: DomainAddArgs<'_>) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let client = hub_client::default_client()?;
    let challenge =
        hub_client::add_custom_domain(&client, &cfg.hub.url, &token.0, &args.domain).await?;
    println!("# Add the following DNS records at your provider for {}:", args.domain);
    println!("_vitonomi.{}.\tTXT\t\"{}\"", args.domain, challenge.txt_record_value);
    println!("{}.\t\tMX 10\t{}.", args.domain, challenge.required_mx_target);
    println!();
    println!("# After publishing, run:");
    println!("#   vitonomi-cli domain verify {}", args.domain);
    Ok(())
}
