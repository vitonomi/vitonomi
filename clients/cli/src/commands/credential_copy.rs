//! `vitonomi-cli credential copy <id> [--field password|totp|username]
//! [--auto-clear 30s]` — clipboard with auto-clear; falls back to
//! stdout on headless hosts.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::{RecordId, RecordType};
use vitonomi_core::totp::generate as totp_generate;
use vitonomi_core::types::credential::{
    CredentialBody, CredentialMetadata, SecretString,
};

use crate::cli::CopyFieldArg;
use crate::commands::clipboard::{copy_with_autoclear, CopyOutcome};
use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialCopyArgs<'a> {
    pub state_path: &'a Path,
    pub id_hex: String,
    pub field: CopyFieldArg,
    pub auto_clear: String,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialCopyArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).map_err(|e| anyhow!("invalid record id: {e}"))?;
    let ttl = humantime::parse_duration(&args.auto_clear)
        .map_err(|e| anyhow!("--auto-clear parse: {e}"))?;
    let session = library_session::open(cfg, args.state_path, prompts).await?;

    let value = match args.field {
        CopyFieldArg::Username => {
            // Username lives in metadata — no body fetch.
            let meta_bytes = session
                .session
                .record_store
                .get_metadata(RecordType::Credential, id)
                .await
                .map_err(|e| anyhow!("get_metadata: {e}"))?
                .ok_or_else(|| anyhow!("credential {id} not found"))?;
            let m = CredentialMetadata::from_metadata_bytes(&meta_bytes)
                .with_context(|| "decode credential metadata")?;
            m.username
                .ok_or_else(|| anyhow!("credential {id} has no username"))?
        }
        CopyFieldArg::Password | CopyFieldArg::Totp => {
            let body_bytes = session
                .session
                .record_store
                .get_body(RecordType::Credential, id)
                .await
                .map_err(|e| anyhow!("get_body: {e}"))?
                .ok_or_else(|| anyhow!("credential {id} has no body"))?;
            let body = CredentialBody::from_body_bytes(&body_bytes)
                .with_context(|| "decode credential body")?;
            match args.field {
                CopyFieldArg::Password => body.password.expose_secret().to_string(),
                CopyFieldArg::Totp => {
                    let totp = body
                        .totp
                        .as_ref()
                        .ok_or_else(|| anyhow!("credential {id} has no TOTP"))?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    totp_generate(totp, now).map_err(|e| anyhow!("totp generate: {e}"))?
                }
                CopyFieldArg::Username => unreachable!(),
            }
        }
    };

    match copy_with_autoclear(SecretString::new(value.clone()), ttl) {
        Ok(CopyOutcome::Copied) => {
            eprintln!("copied (auto-clear in {})", humantime::format_duration(ttl));
        }
        Ok(CopyOutcome::HeadlessFallback) => {
            // No clipboard; fall back to stdout.
            println!("{value}");
            eprintln!("(headless host — printed to stdout instead of clipboard)");
        }
        Err(e) => {
            return Err(anyhow!("clipboard error: {e}"));
        }
    }
    session.shutdown().await;
    Ok(())
}
