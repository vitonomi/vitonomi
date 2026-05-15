//! `vitonomi-cli subdomain list` — print every subdomain the
//! cluster has claimed by walking local `Domain` records on the
//! snapshot chain (filtering for `is_custom == false`).

use std::path::Path;

use anyhow::anyhow;

use vitonomi_core::record::RecordType;
use vitonomi_core::types::domain::DomainMetadata;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct SubdomainListArgs<'a> {
    pub state_path: &'a Path,
}

/// Run.
///
/// # Errors
///
/// Network / state / decode failures.
#[allow(clippy::print_stdout)]
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: SubdomainListArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let listed = session
        .session
        .record_store
        .list_metadata(RecordType::Domain)
        .await
        .map_err(|e| anyhow!("list_metadata: {e}"))?;

    let mut shown = 0usize;
    for (id, bytes) in &listed {
        let m = match DomainMetadata::from_metadata_bytes(bytes) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("(skipping {} — metadata decode: {e})", id.to_hex());
                continue;
            }
        };
        if m.is_custom {
            continue;
        }
        println!(
            "{}  {}  base={}  status={:?}",
            id.to_hex(),
            m.domain,
            m.base_domain.as_deref().unwrap_or("-"),
            m.status
        );
        shown += 1;
    }
    if shown == 0 {
        eprintln!("(no subdomain claims)");
    }
    session.shutdown().await;
    Ok(())
}
