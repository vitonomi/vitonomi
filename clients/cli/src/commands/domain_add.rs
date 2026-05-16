//! `vitonomi-cli domain add <domain>` — register a custom domain
//! with the hub. Hub returns the TXT + MX records to publish at
//! the user's DNS provider, and the CLI writes a local `Pending`
//! `Domain` record so `domain list` and the `alias create`
//! namespace-ownership check see it immediately.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::encoding::b64url_decode;
use vitonomi_core::protocol::wire::domains::DomainStatus;
use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::RecordType;
use vitonomi_core::types::domain::DomainMetadata;
use vitonomi_core::types::FormatVersion;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state;

pub struct DomainAddArgs<'a> {
    pub state_path: &'a Path,
    pub domain: String,
}

/// Run.
///
/// # Errors
///
/// Network / state failures, or local record-store failures.
#[allow(clippy::print_stdout)]
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: DomainAddArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let client = hub_client::default_client()?;
    let challenge =
        hub_client::add_domain(&client, &cfg.hub.url, &token.0, &args.domain).await?;

    // Decode the 32-byte challenge bytes from the hub's base64url-
    // encoded TXT value so the local record holds the canonical
    // form. The local store is purely informational — the hub is
    // authoritative for DNS verification.
    let challenge_bytes = b64url_decode(&challenge.txt_record_value)
        .map_err(|e| anyhow!("decode hub TXT challenge: {e}"))?;
    let challenge_arr: [u8; 32] = challenge_bytes
        .clone()
        .try_into()
        .map_err(|_| anyhow!("hub challenge must be 32 bytes, got {}", challenge_bytes.len()))?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let domain_metadata = DomainMetadata {
        format_version: FormatVersion::V1,
        domain: args.domain.clone(),
        is_custom: true,
        status: DomainStatus::Pending,
        verified_at_ms: None,
        challenge: Some(challenge_arr),
        base_domain: None,
        created_at_ms: now_ms,
    };
    let record_id = DomainMetadata::record_id_for(&args.domain);
    let lib = library_session::open(cfg, args.state_path, prompts).await?;
    let plaintext = RecordPlaintext {
        metadata: domain_metadata
            .to_metadata_bytes()
            .context("encode DomainMetadata")?,
        body: BodyOp::Remove,
    };
    let res = lib
        .session
        .record_store
        .put_or_replace(RecordType::Domain, record_id, plaintext)
        .await;
    lib.shutdown().await;
    res.map_err(|e| anyhow!("write local Domain record: {e}"))?;

    println!("# Add the following DNS records at your provider for {}:", args.domain);
    println!("_vitonomi.{}.\tTXT\t\"{}\"", args.domain, challenge.txt_record_value);
    println!("{}.\t\tMX 10\t{}.", args.domain, challenge.required_mx_target);
    println!();
    println!("# After publishing, run:");
    println!("#   vitonomi-cli domain verify {}", args.domain);
    Ok(())
}
