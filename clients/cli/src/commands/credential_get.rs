//! `vitonomi-cli credential get <id> [--reveal]` — show one
//! credential. Metadata-only by default; `--reveal` triggers a
//! body fetch and prints the secret fields.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::{RecordId, RecordType};
use vitonomi_core::types::credential::{CredentialBody, CredentialMetadata};

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialGetArgs<'a> {
    pub state_path: &'a Path,
    pub id_hex: String,
    pub reveal: bool,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialGetArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).map_err(|e| anyhow!("invalid record id: {e}"))?;
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let meta_bytes = session
        .session
        .record_store
        .get_metadata(RecordType::Credential, id)
        .await
        .map_err(|e| anyhow!("get_metadata: {e}"))?
        .ok_or_else(|| anyhow!("credential {id} not found"))?;
    let meta = CredentialMetadata::from_metadata_bytes(&meta_bytes)
        .with_context(|| "decode credential metadata")?;
    println!("title       {}", meta.title);
    if let Some(url) = &meta.url {
        println!("url         {url}");
    }
    if let Some(username) = &meta.username {
        println!("username    {username}");
    }
    if let Some(folder) = &meta.folder {
        println!("folder      {folder}");
    }
    if !meta.tags.is_empty() {
        println!("tags        {}", meta.tags.join(", "));
    }
    println!("has_totp    {}", meta.has_totp);

    if args.reveal {
        let body_bytes = session
            .session
            .record_store
            .get_body(RecordType::Credential, id)
            .await
            .map_err(|e| anyhow!("get_body: {e}"))?
            .ok_or_else(|| anyhow!("credential {id} has no body face"))?;
        let body = CredentialBody::from_body_bytes(&body_bytes)
            .with_context(|| "decode credential body")?;
        println!("password    {}", body.password.expose_secret());
        if let Some(notes) = &body.notes {
            println!("notes       {notes}");
        }
        if let Some(totp) = &body.totp {
            println!(
                "totp        {} (digits={}, period={}s)",
                hex::encode(totp.secret.expose_secret()),
                totp.digits,
                totp.period_secs
            );
        }
    } else {
        println!("password    [hidden — pass --reveal to fetch body]");
    }
    session.shutdown().await;
    Ok(())
}
