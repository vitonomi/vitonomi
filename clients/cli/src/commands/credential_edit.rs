//! `vitonomi-cli credential edit <id> [--title ...] [--password ...] ...`
//!
//! Edits one or more fields. Editing only metadata fields uses
//! `BodyOp::Keep` and skips body re-seal entirely (asserted by
//! the `credentials_metadata_only_fetch` integration test).

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::{RecordId, RecordType};
use vitonomi_core::types::credential::{CredentialBody, CredentialMetadata, SecretString};

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialEditArgs<'a> {
    pub state_path: &'a Path,
    pub id_hex: String,
    pub title: Option<String>,
    pub url: Option<String>,
    pub username: Option<String>,
    pub folder: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialEditArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).map_err(|e| anyhow!("invalid record id: {e}"))?;
    let session = library_session::open(cfg, args.state_path, prompts).await?;

    // Pull the current metadata.
    let meta_bytes = session
        .session
        .record_store
        .get_metadata(RecordType::Credential, id)
        .await
        .map_err(|e| anyhow!("get_metadata: {e}"))?
        .ok_or_else(|| anyhow!("credential {id} not found"))?;
    let mut meta = CredentialMetadata::from_metadata_bytes(&meta_bytes)
        .with_context(|| "decode credential metadata")?;

    let mut metadata_changed = false;
    if let Some(t) = args.title {
        meta.title = t;
        metadata_changed = true;
    }
    if let Some(u) = args.url {
        meta.url = if u.is_empty() { None } else { Some(u) };
        metadata_changed = true;
    }
    if let Some(u) = args.username {
        meta.username = if u.is_empty() { None } else { Some(u) };
        metadata_changed = true;
    }
    if let Some(f) = args.folder {
        meta.folder = if f.is_empty() { None } else { Some(f) };
        metadata_changed = true;
    }

    let body_changed = args.password.is_some() || args.notes.is_some();
    if !metadata_changed && !body_changed {
        return Err(anyhow!(
            "no fields specified — pass --title / --url / --username / \
             --folder / --password / --notes"
        ));
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    meta.updated_at_ms = now_ms;

    let new_body_op = if body_changed {
        // Pull the current body so we can preserve fields the
        // caller didn't change.
        let body_bytes = session
            .session
            .record_store
            .get_body(RecordType::Credential, id)
            .await
            .map_err(|e| anyhow!("get_body: {e}"))?
            .ok_or_else(|| anyhow!("credential {id} has no body face"))?;
        let mut body = CredentialBody::from_body_bytes(&body_bytes)
            .with_context(|| "decode credential body")?;
        if let Some(p) = args.password {
            body.password = SecretString::new(p);
        }
        if let Some(n) = args.notes {
            body.notes = if n.is_empty() { None } else { Some(n) };
        }
        let new_bytes = body
            .to_body_bytes()
            .map_err(|e| anyhow!("body CBOR: {e}"))?;
        BodyOp::Set(new_bytes)
    } else {
        // Metadata-only edit: skip body re-seal.
        BodyOp::Keep
    };

    let metadata_bytes = meta
        .to_metadata_bytes()
        .map_err(|e| anyhow!("metadata CBOR: {e}"))?;

    session
        .session
        .record_store
        .put_or_replace(
            RecordType::Credential,
            id,
            RecordPlaintext {
                metadata: metadata_bytes,
                body: new_body_op,
            },
        )
        .await
        .map_err(|e| anyhow!("put_or_replace: {e}"))?;
    eprintln!("edited {id}");
    session.shutdown().await;
    Ok(())
}
