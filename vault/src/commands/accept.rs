//! `vitonomi-vault accept --invite <token>` — pull the cluster
//! shared key out of the invite's inner payload, register the
//! vault on the hub, persist the admin-attested fingerprint.

use std::path::Path;

use anyhow::Context as _;

use crate::config::VaultConfig;

pub async fn run(config_path: &Path, mut cfg: VaultConfig, invite: &str) -> anyhow::Result<()> {
    let resp = crate::accept::run(config_path, &mut cfg, invite).await?;
    eprintln!(
        "vault registered: vault_id={} cluster_id={}",
        hex_lower(&resp.vault_id.0),
        hex_lower(resp.cluster_id.as_bytes()),
    );
    eprintln!(
        "  hub.cert_fingerprint persisted: {}",
        cfg.hub.cert_fingerprint
    );
    Ok(())
}

#[allow(dead_code)]
fn _ensure_context(_e: anyhow::Result<()>) {
    // placeholder so `Context as _` is used downstream.
}
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// Suppress unused-import warning for `Context` if the binary
// doesn't end up calling it directly — keep around for symmetry.
#[allow(dead_code)]
fn _ctx_marker() -> anyhow::Result<()> {
    let _: Result<(), anyhow::Error> = Ok::<(), anyhow::Error>(()).context("noop");
    Ok(())
}
