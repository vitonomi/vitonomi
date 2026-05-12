//! `vitonomi-cli record get <type> <id> [-o <path>]` — fetch one
//! record. Defaults to writing the recovered plaintext to stdout.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::{RecordId, RecordType};

use crate::commands::record_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct RecordGetArgs<'a> {
    pub state_path: &'a Path,
    pub record_type: RecordType,
    pub id_hex: String,
    pub out: Option<PathBuf>,
}

/// Recover a record by id.
///
/// # Errors
///
/// I/O / network / crypto failures. Returns an error if the record
/// is unknown (CLI exit code 1 from `run_cli`).
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: RecordGetArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).map_err(|e| anyhow!("invalid RecordId hex: {e}"))?;
    let session = record_session::open(cfg, args.state_path, prompts).await?;
    let bytes = session
        .record_store
        .get(args.record_type, id)
        .await
        .map_err(|e| anyhow!("get record: {e}"))?
        .ok_or_else(|| anyhow!("record {id} not found"))?;
    match args.out {
        Some(path) => {
            std::fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
            eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&bytes).context("write stdout")?;
            let _ = stdout.flush();
        }
    }
    session.shutdown().await;
    Ok(())
}
