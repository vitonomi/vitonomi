//! `vitonomi-cli credential add` — write a fresh credential.
//! Interactive by default; `--file <path.toml>` for scripted use.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use serde::Deserialize;

use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::RecordType;
use vitonomi_core::types::credential::{
    CredentialBody, CredentialMetadata, SecretString,
};
use vitonomi_core::types::FormatVersion;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

#[derive(Debug, Deserialize)]
struct CredentialFile {
    title: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    username: Option<String>,
    password: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

pub struct CredentialAddArgs<'a> {
    pub state_path: &'a Path,
    pub file: Option<PathBuf>,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialAddArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let parsed = match args.file.as_ref() {
        Some(path) => {
            let s = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            toml::from_str::<CredentialFile>(&s).with_context(|| "parse credential TOML")?
        }
        None => CredentialFile {
            title: prompts.username("Title")?,
            url: opt(prompts.username("URL (blank to skip)")?),
            username: opt(prompts.username("Username (blank to skip)")?),
            password: prompts.password("Password", true)?,
            notes: opt(prompts.username("Notes (blank to skip)")?),
            folder: opt(prompts.username("Folder (blank to skip)")?),
            tags: prompts
                .username("Tags (comma-separated, blank to skip)")?
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        },
    };
    if parsed.title.trim().is_empty() {
        return Err(anyhow!("credential title cannot be empty"));
    }

    let now_ms = now_ms();
    let metadata = CredentialMetadata {
        format_version: FormatVersion::V1,
        title: parsed.title,
        url: parsed.url,
        username: parsed.username,
        tags: parsed.tags,
        folder: parsed.folder,
        has_totp: false,
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    let body = CredentialBody {
        format_version: FormatVersion::V1,
        password: SecretString::new(parsed.password),
        totp: None,
        notes: parsed.notes,
        custom_fields: Vec::new(),
    };
    let metadata_bytes = metadata
        .to_metadata_bytes()
        .map_err(|e| anyhow!("metadata CBOR: {e}"))?;
    let body_bytes = body
        .to_body_bytes()
        .map_err(|e| anyhow!("body CBOR: {e}"))?;

    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let id = session
        .session
        .record_store
        .put(
            RecordType::Credential,
            RecordPlaintext {
                metadata: metadata_bytes,
                body: BodyOp::Set(body_bytes),
            },
        )
        .await
        .map_err(|e| anyhow!("put credential: {e}"))?;
    println!("{}", id.to_hex());
    session.shutdown().await;
    Ok(())
}

fn opt(s: String) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
