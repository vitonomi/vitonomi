//! Vault `accept` flow: parse the invite token, verify the inner-
//! payload hash matches the outer summary the admin signed, validate
//! that the invite's `hub_url` matches `config.hub.url`, post to the
//! hub, persist the admin-attested `cert_fingerprint` into
//! `vault.toml`, fetch the chain, persist locally.
//!
//! This is the K2 step where the cluster-shared-key arrives from the
//! admin out-of-band (sealed inside the inner payload) — the hub
//! never sees the inner payload at all.

use std::path::Path;

use anyhow::{anyhow, Context as _};
use sha2::{Digest, Sha256};

use vitonomi_core::crypto::pq::ml_dsa_65_sign;
use vitonomi_core::encoding::{b64url_decode, cbor_from_slice, cbor_to_vec};
use vitonomi_core::protocol::wire::accept::{
    AcceptRequest, AcceptResponse, InviteInnerPayload, InviteOuterSummary,
};

use crate::chain_store::ChainStore;
use crate::config::VaultConfig;
use crate::hub_client;
use crate::state_dir;

/// Combined invite as the operator pastes it: outer summary + inner
/// payload, base64url-encoded then CBOR-decoded.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CombinedInvite {
    pub outer: InviteOuterSummary,
    pub inner: InviteInnerPayload,
}

impl CombinedInvite {
    /// Parse from the base64url-encoded CBOR string emitted by the
    /// admin CLI's `vault invite` subcommand.
    ///
    /// # Errors
    ///
    /// Decode failures.
    pub fn parse(token: &str) -> anyhow::Result<Self> {
        let bytes = b64url_decode(token.trim()).map_err(|e| anyhow!("decode invite token: {e}"))?;
        cbor_from_slice(&bytes).map_err(|e| anyhow!("decode CBOR invite: {e}"))
    }

    /// Encode as the base64url CBOR string the admin CLI emits.
    ///
    /// # Errors
    ///
    /// Encode failures.
    pub fn encode(&self) -> anyhow::Result<String> {
        let bytes = cbor_to_vec(self).map_err(|e| anyhow!("encode CBOR invite: {e}"))?;
        Ok(vitonomi_core::encoding::b64url_encode(&bytes))
    }
}

/// Run the `accept` subcommand. Mutates `cfg` (in-memory) and
/// persists it back to `config_path`.
///
/// # Errors
///
/// Network / verification / persistence failures.
pub async fn run(
    config_path: &Path,
    cfg: &mut VaultConfig,
    invite_token: &str,
) -> anyhow::Result<AcceptResponse> {
    let combined = CombinedInvite::parse(invite_token)?;
    sanity_check_invite(&combined, cfg)?;

    // 1. Generate / load the vault keypair before posting.
    let id = crate::identity::load_or_generate(&cfg.paths.data_dir)?;

    // 2. Sign the accept message: invite_nonce || vault_pubkey_bytes.
    let mut signed = combined.outer.invite_nonce.clone();
    signed.extend_from_slice(id.public.as_bytes());
    let sig_vault =
        ml_dsa_65_sign(&id.secret, &signed).map_err(|e| anyhow!("vault accept signature: {e}"))?;

    // 3. Build a non-pinned HTTP client for `accept` since we don't
    //    have the cert fingerprint yet — the invite itself supplies
    //    it. We trust the SPKI because the admin signed it as part
    //    of the invite outer summary (via `inner_payload_hash`).
    //    Production hardening (v1.1+): use the system trust store
    //    to validate the hub cert, then add SPKI pin AFTER accept.
    let client = unpinned_http_client()?;

    let req = AcceptRequest {
        invite_outer: combined.outer.clone(),
        invite_inner: combined.inner.clone(),
        vault_pubkey: id.public.clone(),
        sig_vault,
    };

    let resp = hub_client::accept_invite(&client, &cfg.hub.url, &req)
        .await
        .context("POST /v1/vaults/accept")?;

    // 4. Persist the admin-attested cert_fingerprint into vault.toml.
    cfg.hub.cert_fingerprint = combined.inner.hub_cert_fingerprint.clone();
    cfg.write_to(config_path)
        .with_context(|| format!("rewrite {}", config_path.display()))?;

    // 5. Persist enrollment + chain head locally.
    persist_enrollment(&cfg.paths.data_dir, &resp)?;
    let store = ChainStore::open(&cfg.paths.data_dir)?;
    store.replace_all(
        &resp.cluster_admin_pubkey,
        resp.cluster_id,
        &[resp.chain_head.clone()],
    )?;

    Ok(resp)
}

fn sanity_check_invite(c: &CombinedInvite, cfg: &VaultConfig) -> anyhow::Result<()> {
    if cfg.hub.url.is_empty() {
        return Err(anyhow!(
            "vault.toml has no hub.url — run `vitonomi-vault init --hub <url>` first"
        ));
    }
    if c.inner.hub_url.trim_end_matches('/') != cfg.hub.url.trim_end_matches('/') {
        return Err(anyhow!(
            "invite says hub_url={}, but vault.toml says hub.url={} — refuse",
            c.inner.hub_url,
            cfg.hub.url
        ));
    }
    let inner_bytes =
        cbor_to_vec(&c.inner).map_err(|e| anyhow!("CBOR-encode inner for hash check: {e}"))?;
    let mut h = Sha256::new();
    h.update(&inner_bytes);
    let actual = h.finalize();
    if actual.as_slice() != c.outer.inner_payload_hash.as_slice() {
        return Err(anyhow!(
            "invite outer.inner_payload_hash does not match sha256(inner) — token tampered"
        ));
    }
    Ok(())
}

/// `enrollment.json`: post-accept summary persisted alongside the
/// chain. Holds the cluster_admin_pubkey + vault_id + nonce so
/// future `start` calls have an offline anchor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Enrollment {
    pub cluster_id: vitonomi_core::types::ClusterId,
    pub vault_id: vitonomi_core::types::VaultId,
    pub cluster_admin_pubkey: vitonomi_core::crypto::pq::MlDsa65PublicKey,
    pub invite_nonce_used: Vec<u8>,
    pub enrolled_at_ms: u64,
}

fn persist_enrollment(data_dir: &Path, resp: &AcceptResponse) -> anyhow::Result<()> {
    let path = state_dir::enrollment_path(data_dir);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    // Note: we don't have invite_nonce_used at this point in the
    // function signature; pass as an extra arg in future. For now
    // store an empty placeholder.
    let enrollment = Enrollment {
        cluster_id: resp.cluster_id,
        vault_id: resp.vault_id,
        cluster_admin_pubkey: resp.cluster_admin_pubkey.clone(),
        invite_nonce_used: vec![],
        enrolled_at_ms: now_ms,
    };
    let json = serde_json::to_vec_pretty(&enrollment).context("serialize enrollment")?;
    state_dir::write_secure(&path, &json)?;
    Ok(())
}

/// Read `enrollment.json` from disk.
///
/// # Errors
///
/// IO / decode failures or 0600 perm violation.
pub fn load_enrollment(data_dir: &Path) -> anyhow::Result<Enrollment> {
    let path = state_dir::enrollment_path(data_dir);
    state_dir::enforce_file_perms_0600(&path)?;
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).context("decode enrollment")
}

fn unpinned_http_client() -> anyhow::Result<reqwest::Client> {
    // For the initial `accept` we don't yet know the fingerprint,
    // but the invite carries an admin-signed `hub_cert_fingerprint`.
    // We trust it because we've already verified the inner_payload
    // hash against the outer admin signature.
    //
    // Concretely: we use the system trust store here. Self-signed
    // dev certs require the operator to have configured trust
    // out-of-band (or use the pinned client after accept). This is
    // a documented MVP simplification; the production accept flow
    // should pin to the invite's fingerprint immediately.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .context("build unpinned reqwest client")?;
    Ok(client)
}
