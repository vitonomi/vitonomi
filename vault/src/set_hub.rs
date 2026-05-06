//! `vitonomi-vault set-hub` — re-point the vault at a new hub
//! (typically after the old one died). Validates that the new hub
//! is serving a chain head consistent with the locally persisted
//! `cluster_admin_pubkey` before rewriting `vault.toml`.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::admin_chain::verify_outer;
use vitonomi_core::types::ClusterId;

use crate::accept::load_enrollment;
use crate::config::VaultConfig;

/// Run the `set-hub` flow.
///
/// # Errors
///
/// Verification / network / persistence failures.
pub async fn run(
    config_path: &Path,
    cfg: &mut VaultConfig,
    new_url: &str,
    new_cert_fingerprint: &str,
) -> anyhow::Result<()> {
    if !new_cert_fingerprint.starts_with("sha256:") {
        return Err(anyhow!(
            "fingerprint must be `sha256:<base64url-no-padding>`, got {new_cert_fingerprint}"
        ));
    }

    // Load the enrollment so we know the cluster_admin_pubkey we
    // must verify the new hub's chain head against.
    let enrollment = load_enrollment(&cfg.paths.data_dir)
        .context("load enrollment.json (have you run `accept` yet?)")?;

    // Hit the new hub's `/v1/admin-chain/{cluster_id}/head` over a
    // pinned client, verify the outer signature against our cached
    // admin pubkey.
    let client = crate::hub_client::pinned_http_client(new_cert_fingerprint)
        .context("build pinned HTTP client for new hub")?;
    let cid_hex = hex_lower(enrollment.cluster_id.as_bytes());

    // Empty bearer here is a placeholder — `set-hub` is operator-
    // initiated and assumes the operator has out-of-band access to
    // their session token. The full implementation will accept a
    // session token via `--token <t>` and pass it through.
    let head = crate::hub_client::get_admin_chain_head(&client, new_url, "", &cid_hex)
        .await
        .context("fetch new hub's chain head")?;
    if head.head.cluster_id != ClusterId(*enrollment.cluster_id.as_bytes()) {
        return Err(anyhow!("new hub's chain head cluster_id mismatch"));
    }
    verify_outer(&enrollment.cluster_admin_pubkey, &head.head)
        .map_err(|e| anyhow!("new hub's chain head signature did not verify: {e}"))?;

    // Persist new hub URL + fingerprint.
    cfg.hub.url = new_url.to_string();
    cfg.hub.cert_fingerprint = new_cert_fingerprint.to_string();
    cfg.write_to(config_path)
        .with_context(|| format!("rewrite {}", config_path.display()))?;
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
