//! `vitonomi-cli alias inbox <id> [--since <seq>]` — fetch new
//! envelopes from the per-alias inbound queue, AEAD-open them with
//! the alias body's KEM secret, and write each as a fresh
//! `AliasMessage` record to the snapshot chain. Hub fetch is
//! always metadata-only at the directory level — only the alias's
//! body face is unsealed (locally) to recover the KEM secret.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::alias_inbound::open_from_alias;
use vitonomi_core::crypto::pq::MlKem768SecretKey;
use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::{RecordId, RecordType};
use vitonomi_core::types::alias::AliasBody;
use vitonomi_core::types::alias_message::{AliasMessageMetadata, ValidationOutcome};
use vitonomi_core::types::FormatVersion;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state;

pub struct AliasInboxArgs<'a> {
    pub state_path: &'a Path,
    pub id_hex: String,
    pub since_seq: u64,
}

/// Poll the inbox.
///
/// # Errors
///
/// Crypto / network / state failures.
#[allow(clippy::print_stdout)]
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: AliasInboxArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let alias_id = RecordId::from_hex(&args.id_hex).context("parse alias id hex")?;
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;

    let session = library_session::open(cfg, args.state_path, prompts).await?;
    // Unseal the alias body (KEM secret) — needed for decapsulation.
    let body_bytes = session
        .session
        .record_store
        .get_body(RecordType::Alias, alias_id)
        .await
        .map_err(|e| anyhow!("get alias body: {e}"))?
        .ok_or_else(|| anyhow!("alias {} body not found", alias_id.to_hex()))?;
    let body = AliasBody::from_body_bytes(&body_bytes).context("decode alias body")?;
    let kem_sk = MlKem768SecretKey(body.alias_kem_secret_key.0.clone());

    let client = hub_client::default_client()?;
    let resp = hub_client::fetch_alias_inbox(
        &client,
        &cfg.hub.url,
        &token.0,
        &alias_id,
        args.since_seq,
    )
    .await?;
    let mut max_seq = args.since_seq;
    let mut written = 0usize;
    for env in &resp.envelopes {
        let plaintext = match open_from_alias(
            &kem_sk,
            env.alias_id,
            env.server_received_at_ms,
            &env.envelope,
        ) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("(skipping seq {} — open: {e})", env.seq);
                continue;
            }
        };
        // Build a minimal `AliasMessage` metadata snapshot. RFC 5322
        // header parsing is intentionally minimal here — the goal of
        // this slice is to land the typed record on the chain so
        // search + read work end-to-end.
        let snippet: String = plaintext
            .iter()
            .take(140)
            .filter(|b| b.is_ascii() && !b.is_ascii_control())
            .map(|b| *b as char)
            .collect();
        let m = AliasMessageMetadata {
            format_version: FormatVersion::V1,
            alias_id,
            sender: String::new(),
            subject: String::new(),
            received_at_ms: env.server_received_at_ms,
            size_bytes: plaintext.len() as u64,
            snippet,
            has_attachments: false,
            attachment_count: 0,
            spf: ValidationOutcome::None,
            dkim: ValidationOutcome::None,
            dmarc: ValidationOutcome::None,
        };
        let pt = RecordPlaintext {
            metadata: m
                .to_metadata_bytes()
                .context("encode AliasMessage metadata")?,
            body: BodyOp::Set(plaintext),
        };
        let msg_id = session
            .session
            .record_store
            .put(RecordType::AliasMessage, pt)
            .await
            .map_err(|e| anyhow!("put alias message: {e}"))?;
        println!("seq={}\tmsg_id={}", env.seq, msg_id.to_hex());
        max_seq = max_seq.max(env.seq);
        written += 1;
    }
    if written > 0 {
        hub_client::ack_alias_inbox(&client, &cfg.hub.url, &token.0, &alias_id, max_seq).await?;
        tracing::info!(written, max_seq, "inbox merged + ack'd");
    } else {
        tracing::info!("no new envelopes");
    }
    session.shutdown().await;
    Ok(())
}
