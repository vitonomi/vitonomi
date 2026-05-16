//! `vitonomi-cli domain verify <domain>` — trigger DNS
//! verification. Hub re-resolves and flips its status to `Verified`
//! if TXT + MX records match; the CLI mirrors that state into the
//! local `Domain` record (status=Verified, verified_at_ms set,
//! challenge cleared).

use std::path::Path;

use anyhow::{anyhow, Context as _};

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

pub struct DomainVerifyArgs<'a> {
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
    args: DomainVerifyArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let client = hub_client::default_client()?;
    let v = hub_client::verify_domain(&client, &cfg.hub.url, &token.0, &args.domain).await?;

    let record_id = DomainMetadata::record_id_for(&args.domain);
    let lib = library_session::open(cfg, args.state_path, prompts).await?;

    // Fetch the existing Pending record to preserve `created_at_ms`.
    // If the record is missing (e.g. `domain add` was never run on
    // this machine, or the record was pruned), fall back to a
    // freshly-built one — the verify response is authoritative for
    // the verified state regardless.
    let existing = lib
        .session
        .record_store
        .get_metadata(RecordType::Domain, record_id)
        .await
        .ok()
        .flatten()
        .and_then(|bytes| DomainMetadata::from_metadata_bytes(&bytes).ok());
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let created_at_ms = existing
        .as_ref()
        .map(|d| d.created_at_ms)
        .unwrap_or(now_ms);
    let updated = DomainMetadata {
        format_version: FormatVersion::V1,
        domain: v.domain.clone(),
        is_custom: true,
        status: DomainStatus::Verified,
        verified_at_ms: Some(v.verified_at_ms),
        challenge: None,
        base_domain: None,
        created_at_ms,
    };
    let plaintext = RecordPlaintext {
        metadata: updated
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
    res.map_err(|e| anyhow!("update local Domain record: {e}"))?;

    tracing::info!(domain = %v.domain, verified_at_ms = v.verified_at_ms, "domain verified");
    Ok(())
}
