//! `vitonomi-cli credential import --format <fmt> <file>`

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};

use vitonomi_core::credentials::import::{import, ImportFormat};
use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::RecordType;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialImportArgs<'a> {
    pub state_path: &'a Path,
    pub format: ImportFormat,
    pub file: PathBuf,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialImportArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(&args.file)
        .with_context(|| format!("read import file {}", args.file.display()))?;
    let imported = import(args.format, std::io::Cursor::new(bytes))
        .map_err(|e| anyhow!("parse {:?}: {e}", args.format))?;
    let count = imported.len();
    eprintln!("parsed {count} credential(s) from {}", args.file.display());

    let session = library_session::open(cfg, args.state_path, prompts).await?;
    for (meta, body) in imported {
        let mb = meta.to_metadata_bytes().map_err(|e| anyhow!("metadata CBOR: {e}"))?;
        let bb = body.to_body_bytes().map_err(|e| anyhow!("body CBOR: {e}"))?;
        let id = session
            .session
            .record_store
            .put(
                RecordType::Credential,
                RecordPlaintext {
                    metadata: mb,
                    body: BodyOp::Set(bb),
                },
            )
            .await
            .map_err(|e| anyhow!("put credential: {e}"))?;
        eprintln!("imported {id}");
    }
    session.shutdown().await;
    Ok(())
}
