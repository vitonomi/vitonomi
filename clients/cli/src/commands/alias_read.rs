//! `vitonomi-cli alias read <alias-id> <message-id>` — fetch the
//! body of a stored `AliasMessage` and print to stdout.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::{RecordId, RecordType};

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct AliasReadArgs<'a> {
    pub state_path: &'a Path,
    pub alias_id_hex: String,
    pub message_id_hex: String,
}

/// Run.
///
/// # Errors
///
/// Crypto / network / state failures.
#[allow(clippy::print_stdout)]
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: AliasReadArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    // alias_id is parsed but not used here — it is kept in the CLI
    // surface so that future privacy work (e.g. asserting the
    // message belongs to this alias) has a clear hook.
    let _ = RecordId::from_hex(&args.alias_id_hex).context("parse alias id hex")?;
    let msg_id = RecordId::from_hex(&args.message_id_hex).context("parse message id hex")?;
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let body = session
        .session
        .record_store
        .get_body(RecordType::AliasMessage, msg_id)
        .await
        .map_err(|e| anyhow!("get alias message body: {e}"))?
        .ok_or_else(|| anyhow!("alias message {} body not found", msg_id.to_hex()))?;
    // Print as bytes so binary MIME survives.
    use std::io::Write as _;
    std::io::stdout()
        .write_all(&body)
        .context("write body to stdout")?;
    session.shutdown().await;
    Ok(())
}
