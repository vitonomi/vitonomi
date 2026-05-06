//! `vitonomi-cli vault list` — fetch the cluster's vault directory
//! from the hub. Verifies the chain head's outer admin signature
//! against the cached `cluster_admin_pubkey` so a malicious hub
//! cannot fabricate vaults.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::admin_chain::verify_outer;

use crate::config::CliConfig;
use crate::hub_client;
use crate::state;

pub async fn run(cfg: &CliConfig, state_path: &Path) -> anyhow::Result<()> {
    let st = state::load(state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;

    let client = hub_client::default_client()?;
    let head = hub_client::get_admin_chain_head(&client, &cfg.hub.url, &token.0, &st.cluster_id)
        .await
        .context("GET /v1/admin-chain/_/head")?;
    verify_outer(&st.cluster_admin_pubkey, &head.head)
        .map_err(|e| anyhow!("hub's chain head failed signature check: {e}"))?;

    let listing = hub_client::list_vaults(&client, &cfg.hub.url, &token.0)
        .await
        .context("GET /v1/vaults")?;

    if listing.vaults.is_empty() {
        println!("no vaults registered yet");
        return Ok(());
    }
    println!(
        "{:<32}  {:<10}  {:<13}  {}",
        "vault_id", "status", "last_seen_ms", "pubkey_b64_prefix"
    );
    for v in listing.vaults {
        println!(
            "{:<32}  {:<10}  {:<13}  {}",
            hex_lower(&v.vault_id.0),
            format!("{:?}", v.status).to_lowercase(),
            v.last_seen_ms
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".into()),
            shortish(v.vault_pubkey.as_bytes()),
        );
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn shortish(bytes: &[u8]) -> String {
    let s = vitonomi_core::encoding::b64url_encode(bytes);
    if s.len() <= 24 {
        s
    } else {
        format!("{}…", &s[..24])
    }
}
