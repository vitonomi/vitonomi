//! Vault → hub auto-bootstrap. Re-creates a cluster + vault
//! registration on a hub that has no record (typical after an
//! `InMemoryHub`-backed reboot, or a deliberate hub migration).
//!
//! Inputs come entirely from on-disk vault state:
//! - `enrollment.json` — `cluster_admin_pubkey` + persisted
//!   `invite_outer` + `sig_vault` (the membership proof captured at
//!   first accept)
//! - `chain_store/` — the local chain copy (vaults are authoritative
//!   for chain integrity)
//! - `identity.bin` — the vault keypair
//!
//! Idempotent: the hub returns the existing `vault_id` if the
//! cluster + vault are already registered, in which case we still
//! double-check the enrollment file for drift and rewrite if needed.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::protocol::wire::bootstrap::BootstrapRequest;

use crate::accept::{load_enrollment, store_enrollment, Enrollment};
use crate::chain_store::ChainStore;
use crate::config::VaultConfig;
use crate::hub_client;
use crate::identity::VaultIdentity;

/// Run auto-bootstrap. Returns the (possibly-updated) enrollment.
///
/// # Errors
///
/// Missing membership proof in enrollment, missing chain, network /
/// status / decode failures.
pub async fn run(cfg: &VaultConfig, identity: &VaultIdentity) -> anyhow::Result<Enrollment> {
    let mut enrollment = load_enrollment(&cfg.paths.data_dir)
        .context("load enrollment.json (have you run `accept`?)")?;
    bootstrap_with(cfg, identity, &mut enrollment).await?;
    Ok(enrollment)
}

/// Lower-level entry point: take a borrowed enrollment, run
/// bootstrap, mutate-in-place, and persist any changes.
///
/// # Errors
///
/// As [`run`].
pub async fn bootstrap_with(
    cfg: &VaultConfig,
    identity: &VaultIdentity,
    enrollment: &mut Enrollment,
) -> anyhow::Result<()> {
    let invite_outer = enrollment.invite_outer.clone().ok_or_else(|| {
        anyhow!(
            "enrollment.json predates auto-bootstrap support \
             (missing invite_outer); re-run `accept` to regenerate"
        )
    })?;
    let sig_vault = enrollment.sig_vault.clone().ok_or_else(|| {
        anyhow!(
            "enrollment.json predates auto-bootstrap support \
             (missing sig_vault); re-run `accept` to regenerate"
        )
    })?;

    let chain_export = ChainStore::open(&cfg.paths.data_dir)?
        .read_all()
        .context("read local chain")?;
    if chain_export.is_empty() {
        return Err(anyhow!("local chain is empty — refusing to bootstrap"));
    }

    let req = BootstrapRequest {
        cluster_admin_pubkey: enrollment.cluster_admin_pubkey.clone(),
        chain_export,
        vault_pubkey: identity.public.clone(),
        invite_outer,
        sig_vault,
    };

    let client = http_client(&cfg.hub.url, &cfg.hub.cert_fingerprint)?;
    let resp = hub_client::bootstrap_cluster(&client, &cfg.hub.url, &req)
        .await
        .context("POST /v1/clusters/bootstrap")?;

    if resp.created_cluster || resp.created_vault {
        tracing::info!(
            created_cluster = resp.created_cluster,
            created_vault = resp.created_vault,
            "auto-bootstrap registered cluster/vault on the hub"
        );
    } else {
        tracing::debug!("auto-bootstrap was a no-op (cluster + vault already registered)");
    }

    if resp.vault_id != enrollment.vault_id {
        tracing::info!(
            old = ?enrollment.vault_id,
            new = ?resp.vault_id,
            "hub assigned a new vault_id — persisting"
        );
        enrollment.vault_id = resp.vault_id;
        store_enrollment(&cfg.paths.data_dir, enrollment).context("persist updated enrollment")?;
    }
    Ok(())
}

/// Build the right reqwest client for the configured hub URL. https
/// gets the SPKI-pinned client; http (test scenarios only) gets a
/// plain client.
fn http_client(hub_url: &str, cert_fingerprint: &str) -> anyhow::Result<reqwest::Client> {
    if hub_url.starts_with("http://") {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("build plain reqwest client")
    } else {
        if cert_fingerprint.is_empty() {
            return Err(anyhow!(
                "https hub configured but cert_fingerprint is empty — run `accept` first"
            ));
        }
        hub_client::pinned_http_client(cert_fingerprint)
    }
}

/// Path-aware shorthand used in tests that bypass `cfg.hub.url`
/// (e.g., when targeting a fresh hub-B before `set-hub` rewrites
/// `vault.toml`).
///
/// # Errors
///
/// As [`bootstrap_with`], plus client construction.
pub async fn bootstrap_to(
    data_dir: &Path,
    hub_url: &str,
    cert_fingerprint: &str,
    identity: &VaultIdentity,
) -> anyhow::Result<Enrollment> {
    let mut enrollment = load_enrollment(data_dir)?;
    let invite_outer = enrollment
        .invite_outer
        .clone()
        .ok_or_else(|| anyhow!("enrollment missing invite_outer"))?;
    let sig_vault = enrollment
        .sig_vault
        .clone()
        .ok_or_else(|| anyhow!("enrollment missing sig_vault"))?;
    let chain_export = ChainStore::open(data_dir)?.read_all()?;
    if chain_export.is_empty() {
        return Err(anyhow!("local chain is empty"));
    }
    let req = BootstrapRequest {
        cluster_admin_pubkey: enrollment.cluster_admin_pubkey.clone(),
        chain_export,
        vault_pubkey: identity.public.clone(),
        invite_outer,
        sig_vault,
    };
    let client = http_client(hub_url, cert_fingerprint)?;
    let resp = hub_client::bootstrap_cluster(&client, hub_url, &req).await?;
    if resp.vault_id != enrollment.vault_id {
        enrollment.vault_id = resp.vault_id;
        store_enrollment(data_dir, &enrollment)?;
    }
    Ok(enrollment)
}
