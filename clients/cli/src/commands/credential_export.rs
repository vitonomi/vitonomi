//! `vitonomi-cli credential export --format vitonomi-backup|json
//! [--force-plain] <file>`

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};

use vitonomi_core::credentials::export::{json::export_json, vitonomi_backup, ExportItem};
use vitonomi_core::crypto::argon2::Argon2Params;
use vitonomi_core::record::RecordType;
use vitonomi_core::types::credential::{CredentialBody, CredentialMetadata};

use crate::cli::ExportFormatArg;
use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialExportArgs<'a> {
    pub state_path: &'a Path,
    pub format: ExportFormatArg,
    pub file: PathBuf,
    pub force_plain: bool,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialExportArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let listed = session
        .session
        .record_store
        .list_metadata(RecordType::Credential)
        .await
        .map_err(|e| anyhow!("list_metadata: {e}"))?;

    // Pull every body face. Yes — body fetches happen here. This
    // is the one credential operation where that's intentional.
    let mut items: Vec<ExportItem> = Vec::with_capacity(listed.len());
    for (id, mb) in listed {
        let m = CredentialMetadata::from_metadata_bytes(&mb)
            .with_context(|| format!("decode metadata for {id}"))?;
        let bb = session
            .session
            .record_store
            .get_body(RecordType::Credential, id)
            .await
            .map_err(|e| anyhow!("get_body for {id}: {e}"))?
            .ok_or_else(|| anyhow!("credential {id} has no body"))?;
        let b = CredentialBody::from_body_bytes(&bb)
            .with_context(|| format!("decode body for {id}"))?;
        items.push((m, b));
    }

    match args.format {
        ExportFormatArg::VitonomiBackup => {
            // Confirm-twice for the export passphrase.
            let pass = prompts.password("Export passphrase", true)?;
            let bytes = vitonomi_backup::encrypt(&items, pass.as_bytes(), prod_argon_params())
                .map_err(|e| anyhow!("vitonomi-backup encrypt: {e}"))?;
            std::fs::write(&args.file, &bytes)
                .with_context(|| format!("write {}", args.file.display()))?;
            eprintln!(
                "wrote {} credentials to {} (encrypted)",
                items.len(),
                args.file.display()
            );
        }
        ExportFormatArg::Json => {
            if !args.force_plain {
                return Err(anyhow!(
                    "plaintext JSON export refused without --force-plain. \
                     This will write every password in the clear; if that's \
                     intentional, re-run with --force-plain."
                ));
            }
            // Confirm twice via the prompts trait.
            let confirm = prompts.username("Type 'yes' to confirm plaintext export")?;
            if confirm.trim() != "yes" {
                return Err(anyhow!("aborted (no confirmation)"));
            }
            let s = export_json(&items, true).map_err(|e| anyhow!("json export: {e}"))?;
            std::fs::write(&args.file, s)
                .with_context(|| format!("write {}", args.file.display()))?;
            eprintln!(
                "wrote {} credentials to {} (PLAINTEXT)",
                items.len(),
                args.file.display()
            );
        }
    }
    session.shutdown().await;
    Ok(())
}

fn prod_argon_params() -> Argon2Params {
    Argon2Params {
        mem_kib: 256 * 1024,
        time_cost: 3,
        parallelism: 1,
        out_len: 32,
    }
}
