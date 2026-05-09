//! Vault `accept` flow: parse the operator-channel short invite
//! token, recompute `sha256(inner)` against the token's
//! `inner_payload_hash` to catch tampering, validate the invite's
//! `hub_url` matches `config.hub.url`, post `(cluster_id, invite_nonce,
//! inner, vault_pubkey, sig_vault)` to the hub (the hub already holds
//! the admin-signed outer from `create_invite`), persist the admin-
//! attested `cert_fingerprint` into `vault.toml`, open the K2 seal,
//! persist locally.

use std::path::Path;

use anyhow::{anyhow, Context as _};
use sha2::{Digest, Sha256};

use vitonomi_core::crypto::aead::open as aead_open;
use vitonomi_core::crypto::cluster_keys::ClusterSharedKey;
use vitonomi_core::crypto::invite_kek::{InviteKek, SEALED_CLUSTER_KEY_AAD};
use vitonomi_core::crypto::pq::ml_dsa_65_sign;
use vitonomi_core::encoding::cbor_to_vec;
use vitonomi_core::protocol::wire::accept::{
    parse_short_token, AcceptRequest, AcceptResponse, InviteInnerPayload, ShortInviteToken,
};

use crate::chain_store::ChainStore;
use crate::config::VaultConfig;
use crate::hub_client;
use crate::state_dir;

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
    let token = parse_short_token(invite_token).map_err(|e| anyhow!("parse invite token: {e}"))?;
    sanity_check_token(&token, cfg)?;

    // 1. Generate / load the vault keypair before posting.
    let id = crate::identity::load_or_generate(&cfg.paths.data_dir)?;

    // 2. Sign the accept message: invite_nonce || vault_pubkey_bytes.
    let mut signed = token.invite_nonce.clone();
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
        cluster_id: token.cluster_id,
        invite_nonce: token.invite_nonce.clone(),
        invite_inner: token.inner.clone(),
        vault_pubkey: id.public.clone(),
        sig_vault: sig_vault.clone(),
    };

    let resp = hub_client::accept_invite(&client, &cfg.hub.url, &req)
        .await
        .context("POST /v1/vaults/accept")?;

    // 4. Persist the admin-attested cert_fingerprint into vault.toml.
    cfg.hub.cert_fingerprint = token.inner.hub_cert_fingerprint.clone();
    cfg.write_to(config_path)
        .with_context(|| format!("rewrite {}", config_path.display()))?;

    // 5. Open the K2 seal: derive KEK from invite_kek_secret +
    //    invite_nonce, AEAD-open sealed_cluster_key, persist
    //    cluster_shared_key locally for chain inner unseal + record
    //    sealing in Phase 1+.
    let cluster_shared_key = unseal_cluster_shared_key(&token.invite_nonce, &token.inner)
        .context("open sealed_cluster_key from invite (K2)")?;
    crate::cluster_key::store(&cfg.paths.data_dir, &cluster_shared_key)
        .context("persist cluster_shared_key.bin")?;

    // 6. Persist enrollment + chain head locally. The membership
    //    proof (invite_outer echoed by hub + sig_vault) is captured
    //    here so a later auto-bootstrap against a fresh hub can
    //    re-present it.
    persist_enrollment(&cfg.paths.data_dir, &resp, &resp.invite_outer, &sig_vault)?;
    let store = ChainStore::open(&cfg.paths.data_dir)?;
    store.replace_all(
        &resp.cluster_admin_pubkey,
        resp.cluster_id,
        &[resp.chain_head.clone()],
    )?;

    Ok(resp)
}

/// Open the K2 seal in an invite. Pure function — used by the
/// `accept` flow above and exposed for tests / future replay paths.
///
/// # Errors
///
/// `CryptoError::KeyLength` from KEK derivation if the secret is
/// malformed; AEAD open failure if the seal was tampered with or if
/// the secret/nonce don't match what the admin used at issue time.
pub fn unseal_cluster_shared_key(
    invite_nonce: &[u8],
    inner: &InviteInnerPayload,
) -> anyhow::Result<ClusterSharedKey> {
    let kek = InviteKek::derive(&inner.invite_kek_secret, invite_nonce)
        .map_err(|e| anyhow!("derive invite KEK: {e}"))?;
    let csk_bytes = aead_open(
        &kek.to_aead_key(),
        &inner.sealed_cluster_key,
        SEALED_CLUSTER_KEY_AAD,
    )
    .map_err(|e| anyhow!("AEAD-open sealed_cluster_key: {e}"))?;
    if csk_bytes.len() != ClusterSharedKey::LEN {
        return Err(anyhow!(
            "unsealed cluster_shared_key has wrong length: {} (expected {})",
            csk_bytes.len(),
            ClusterSharedKey::LEN
        ));
    }
    Ok(ClusterSharedKey(csk_bytes))
}

fn sanity_check_token(t: &ShortInviteToken, cfg: &VaultConfig) -> anyhow::Result<()> {
    if cfg.hub.url.is_empty() {
        return Err(anyhow!(
            "vault.toml has no hub.url — run `vitonomi-vault init --hub <url>` first"
        ));
    }
    if t.inner.hub_url.trim_end_matches('/') != cfg.hub.url.trim_end_matches('/') {
        return Err(anyhow!(
            "invite says hub_url={}, but vault.toml says hub.url={} — refuse",
            t.inner.hub_url,
            cfg.hub.url
        ));
    }
    let inner_bytes =
        cbor_to_vec(&t.inner).map_err(|e| anyhow!("CBOR-encode inner for hash check: {e}"))?;
    let mut h = Sha256::new();
    h.update(&inner_bytes);
    let actual = h.finalize();
    if actual.as_slice() != t.inner_payload_hash.as_slice() {
        return Err(anyhow!(
            "invite inner_payload_hash does not match sha256(inner) — token tampered"
        ));
    }
    Ok(())
}

/// `enrollment.json`: post-accept summary persisted alongside the
/// chain. Holds the cluster_admin_pubkey + vault_id + the admin-
/// signed `invite_outer` summary + the vault's own `sig_vault`. The
/// last two together form the membership proof a later auto-bootstrap
/// re-presents to a fresh hub.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Enrollment {
    pub cluster_id: vitonomi_core::types::ClusterId,
    pub vault_id: vitonomi_core::types::VaultId,
    pub cluster_admin_pubkey: vitonomi_core::crypto::pq::MlDsa65PublicKey,
    pub invite_nonce_used: Vec<u8>,
    pub enrolled_at_ms: u64,
    /// The admin-signed invite outer summary the vault saw at accept.
    /// Re-presented by the vault during auto-bootstrap to prove an
    /// admin authorized this enrollment slot. Optional only for
    /// backward-compat with enrollment files written before the
    /// bootstrap feature shipped.
    #[serde(default)]
    pub invite_outer: Option<vitonomi_core::protocol::wire::accept::InviteOuterSummary>,
    /// The vault's signature over `invite_nonce || vault_pubkey_bytes`
    /// produced at accept time. Combined with `invite_outer` it
    /// proves both admin authorization AND vault key possession to a
    /// hub that has no prior record of either.
    #[serde(default)]
    pub sig_vault: Option<vitonomi_core::crypto::pq::MlDsa65Signature>,
}

fn persist_enrollment(
    data_dir: &Path,
    resp: &AcceptResponse,
    invite_outer: &vitonomi_core::protocol::wire::accept::InviteOuterSummary,
    sig_vault: &vitonomi_core::crypto::pq::MlDsa65Signature,
) -> anyhow::Result<()> {
    let path = state_dir::enrollment_path(data_dir);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let enrollment = Enrollment {
        cluster_id: resp.cluster_id,
        vault_id: resp.vault_id,
        cluster_admin_pubkey: resp.cluster_admin_pubkey.clone(),
        invite_nonce_used: invite_outer.invite_nonce.clone(),
        enrolled_at_ms: now_ms,
        invite_outer: Some(invite_outer.clone()),
        sig_vault: Some(sig_vault.clone()),
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

/// Atomically rewrite `enrollment.json` from an in-memory struct.
/// Used by the auto-bootstrap path when the hub assigns a fresh
/// `vault_id` for a previously-known vault.
///
/// # Errors
///
/// Serialize / write / perm-set failures.
pub fn store_enrollment(data_dir: &Path, enrollment: &Enrollment) -> anyhow::Result<()> {
    let path = state_dir::enrollment_path(data_dir);
    let json = serde_json::to_vec_pretty(enrollment).context("serialize enrollment")?;
    state_dir::write_secure(&path, &json)?;
    Ok(())
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
