//! `vitonomi-cli record put <type> --metadata-file <path> [--body-file <path>]`
//! — upload a new record. The metadata face is the small searchable
//! face (always required); the body face is optional.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::RecordType;

use crate::commands::record_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct RecordPutArgs<'a> {
    pub state_path: &'a Path,
    pub record_type: RecordType,
    /// File holding the metadata face bytes.
    pub metadata_file: PathBuf,
    /// Optional file holding the body face bytes. `None` writes a
    /// metadata-only record.
    pub body_file: Option<PathBuf>,
}

/// Read `args.metadata_file` (and optionally `args.body_file`), put
/// the resulting plaintext through the snapshot chain via libp2p,
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
    let metadata = std::fs::read(&args.metadata_file)
        .with_context(|| format!("read metadata file {}", args.metadata_file.display()))?;
    if metadata.is_empty() {
        return Err(anyhow!("metadata file is empty"));
    }

    let body = match args.body_file.as_ref() {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("read body file {}", path.display()))?;
            BodyOp::Set(bytes)
        }
        None => BodyOp::Remove,
    };

    let session = record_session::open(cfg, args.state_path, prompts).await?;
    let id = session
        .record_store
        .put(args.record_type, RecordPlaintext { metadata, body })
        .await
        .map_err(|e| anyhow!("put record: {e}"))?;
    println!("{}", id.to_hex());
    session.shutdown().await;
    Ok(())
}
