//! `vitonomi-cli credential list [--folder <f>] [--tag <t>]` —
//! print every credential's metadata. Body chunks are NEVER
//! fetched.

use std::path::Path;

use anyhow::anyhow;

use vitonomi_core::record::RecordType;
use vitonomi_core::types::credential::CredentialMetadata;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialListArgs<'a> {
    pub state_path: &'a Path,
    pub folder: Option<String>,
    pub tag: Option<String>,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialListArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let listed = session
        .session
        .record_store
        .list_metadata(RecordType::Credential)
        .await
        .map_err(|e| anyhow!("list_metadata: {e}"))?;

    let mut shown = 0usize;
    for (id, bytes) in &listed {
        let m = match CredentialMetadata::from_metadata_bytes(bytes) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("(skipping {} — metadata decode: {e})", id.to_hex());
                continue;
            }
        };
        if let Some(f) = args.folder.as_deref() {
            if m.folder.as_deref() != Some(f) {
                continue;
            }
        }
        if let Some(t) = args.tag.as_deref() {
            if !m.tags.iter().any(|x| x == t) {
                continue;
            }
        }
        let url = m.url.as_deref().unwrap_or("");
        let user = m.username.as_deref().unwrap_or("");
        let totp = if m.has_totp { " [TOTP]" } else { "" };
        println!("{}  {}  {} ({}){}", id.to_hex(), m.title, url, user, totp);
        shown += 1;
    }
    if shown == 0 {
        eprintln!("(no credentials match)");
    }
    session.shutdown().await;
    Ok(())
}
