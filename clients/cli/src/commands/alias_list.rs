//! `vitonomi-cli alias list` — print every alias's metadata.

use std::path::Path;

use anyhow::anyhow;

use vitonomi_core::record::RecordType;
use vitonomi_core::types::alias::AliasMetadata;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct AliasListArgs<'a> {
    pub state_path: &'a Path,
}

/// Run.
///
/// # Errors
///
/// Crypto / network / state failures.
#[allow(clippy::print_stdout)]
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: AliasListArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let listed = session
        .session
        .record_store
        .list_metadata(RecordType::Alias)
        .await
        .map_err(|e| anyhow!("list_metadata: {e}"))?;
    let mut shown = 0usize;
    for (id, bytes) in &listed {
        let m = match AliasMetadata::from_metadata_bytes(bytes) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("(skipping {} — decode: {e})", id.to_hex());
                continue;
            }
        };
        let label = m.label.as_deref().unwrap_or("");
        let status = if m.active { "active" } else { "disabled" };
        println!(
            "{}  {}  ({})  {}  tags={:?}",
            id.to_hex(),
            m.full_address(),
            status,
            label,
            m.tags
        );
        shown += 1;
    }
    if shown == 0 {
        eprintln!("(no aliases)");
    }
    session.shutdown().await;
    Ok(())
}
