//! `vitonomi-cli credential totp <id> [--watch]` — print the
//! current TOTP code for a credential. Body fetch required.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context as _};

use vitonomi_core::record::{RecordId, RecordType};
use vitonomi_core::totp::{generate, next_window};
use vitonomi_core::types::credential::CredentialBody;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialTotpArgs<'a> {
    pub state_path: &'a Path,
    pub id_hex: String,
    pub watch: bool,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialTotpArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let id = RecordId::from_hex(&args.id_hex).map_err(|e| anyhow!("invalid record id: {e}"))?;
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let body_bytes = session
        .session
        .record_store
        .get_body(RecordType::Credential, id)
        .await
        .map_err(|e| anyhow!("get_body: {e}"))?
        .ok_or_else(|| anyhow!("credential {id} has no body face"))?;
    let body = CredentialBody::from_body_bytes(&body_bytes)
        .with_context(|| "decode credential body")?;
    let totp = body.totp.as_ref().ok_or_else(|| {
        anyhow!("credential {id} has no TOTP entry — use `credential edit` to add one")
    })?;

    loop {
        let now = unix_secs();
        let code = generate(totp, now).map_err(|e| anyhow!("totp generate: {e}"))?;
        let until = next_window(totp, now);
        let secs_left = until.saturating_sub(now);
        if args.watch {
            print!("\r{code}  ({secs_left}s left)   ");
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
            tokio::time::sleep(Duration::from_secs(secs_left.max(1))).await;
        } else {
            println!("{code}");
            break;
        }
    }
    session.shutdown().await;
    Ok(())
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
