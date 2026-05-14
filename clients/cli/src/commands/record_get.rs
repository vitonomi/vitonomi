//! `vitonomi-cli record get <type> <id> [--face metadata|body] [-o <path>]`
//! — fetch one face of a record. Defaults to the metadata face
//! (cheap, no body chunks touched). `--face body` fetches that one
//! record's body chunks.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::{RecordId, RecordType};

use crate::cli::RecordFaceArg;
use crate::commands::record_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

/// Which face of a record to fetch. Mirrors [`RecordFaceArg`] without
/// pulling clap into the command-module API surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordFace {
    Metadata,
    Body,
}

impl From<RecordFaceArg> for RecordFace {
    fn from(arg: RecordFaceArg) -> Self {
        match arg {
            RecordFaceArg::Metadata => Self::Metadata,
            RecordFaceArg::Body => Self::Body,
        }
    }
}

pub struct RecordGetArgs<'a> {
    pub state_path: &'a Path,
    pub record_type: RecordType,
    pub id_hex: String,
    pub face: RecordFace,
    pub out: Option<PathBuf>,
}

/// Recover one face of a record by id.
///
/// # Errors
///
/// I/O / network / crypto failures. Returns an error if the record
/// (or the requested face) is unknown.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: RecordGetArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).map_err(|e| anyhow!("invalid RecordId hex: {e}"))?;
    let session = record_session::open(cfg, args.state_path, prompts).await?;
    let bytes = match args.face {
        RecordFace::Metadata => session
            .record_store
            .get_metadata(args.record_type, id)
            .await
            .map_err(|e| anyhow!("get metadata: {e}"))?
            .ok_or_else(|| anyhow!("record {id} not found"))?,
        RecordFace::Body => session
            .record_store
            .get_body(args.record_type, id)
            .await
            .map_err(|e| anyhow!("get body: {e}"))?
            .ok_or_else(|| anyhow!("record {id} has no body face"))?,
    };
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
