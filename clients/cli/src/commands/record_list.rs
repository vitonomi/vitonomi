//! `vitonomi-cli record list <type>` — print every record id of the
//! given type, one per line, with a short hex-encoded preview.

use std::path::Path;

use anyhow::anyhow;

use vitonomi_core::record::RecordType;

use crate::commands::record_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct RecordListArgs<'a> {
    pub state_path: &'a Path,
    pub record_type: RecordType,
}

const PREVIEW_BYTES: usize = 16;

/// List records of the given type.
///
/// # Errors
///
/// I/O / network / crypto failures.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: RecordListArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let session = record_session::open(cfg, args.state_path, prompts).await?;
    let listed = session
        .record_store
        .list(args.record_type)
        .await
        .map_err(|e| anyhow!("list records: {e}"))?;
    if listed.is_empty() {
        eprintln!("(no records of type {:?})", args.record_type);
    } else {
        for (id, bytes) in &listed {
            let preview: String = bytes
                .iter()
                .take(PREVIEW_BYTES)
                .map(|b| format!("{b:02x}"))
                .collect();
            let dots = if bytes.len() > PREVIEW_BYTES {
                "…"
            } else {
                ""
            };
            println!("{}  {} bytes  {preview}{dots}", id.to_hex(), bytes.len());
        }
    }
    session.shutdown().await;
    Ok(())
}
