//! `vitonomi-cli record put <type> --file <path>` — upload a file as
//! a new record.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::RecordType;

use crate::commands::record_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct RecordPutArgs<'a> {
    pub state_path: &'a Path,
    pub record_type: RecordType,
    pub file: PathBuf,
}

/// Read `args.file`, put it through the snapshot chain via libp2p,
/// print the new RecordId hex to stdout.
///
/// # Errors
///
/// I/O / network / crypto failures.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: RecordPutArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let bytes =
        std::fs::read(&args.file).with_context(|| format!("read {}", args.file.display()))?;
    if bytes.is_empty() {
        return Err(anyhow!(
            "record file is empty — vitonomi records must carry payload bytes"
        ));
    }

    let session = record_session::open(cfg, args.state_path, prompts).await?;
    let id = session
        .record_store
        .put(args.record_type, &bytes)
        .await
        .map_err(|e| anyhow!("put record: {e}"))?;
    println!("{}", id.to_hex());
    session.shutdown().await;
    Ok(())
}
