//! `vitonomi-cli vault invite --name <n>` — admin-only. Prompts
//! password (re-unlocks the cluster admin sk from the locally
//! cached blob), generates a fresh `invite_nonce`, builds the
//! outer summary signing it with the admin sk, builds the inner
//! payload sealing `cluster_shared_key` under a per-invite KEK,
//! POSTs the outer summary to the hub, and emits the combined
//! base64url-CBOR token for the operator to transmit out-of-band.

use std::path::Path;

use anyhow::{anyhow, Context as _};
use sha2::{Digest, Sha256};

use vitonomi_core::crypto::aead::{seal, AeadKey};
use vitonomi_core::crypto::cluster_keys::{ClusterPepper, ClusterSharedKey};
use vitonomi_core::crypto::invite_kek::InviteKek;
use vitonomi_core::crypto::keyblob::decrypt_with_password;
use vitonomi_core::crypto::pq::{ml_dsa_65_sign, MlDsa65SecretKey};
use vitonomi_core::crypto::random::random_bytes;
use vitonomi_core::encoding::{b64url_encode, cbor_to_vec};
use vitonomi_core::protocol::wire::accept::{
    CreateInviteRequest, InviteInnerPayload, InviteOuterSummary, VaultRole,
};
use vitonomi_core::types::FormatVersion;

use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state;

pub struct VaultInviteArgs<'a> {
    pub state_path: &'a Path,
    pub vault_name: String,
    pub hub_cert_fingerprint: String,
    pub ttl_secs: u64,
}

/// Run the invite flow. Returns the combined invite token (CBOR
/// then base64url) for the operator to transmit out-of-band.
///
/// # Errors
///
/// Crypto / network / state / prompt failures.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: VaultInviteArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<String> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let _ = ClusterPepper(st.cluster_pepper.clone()); // ensure import is wired

    // Re-prompt password and unseal the cluster admin sk.
    let password = prompts.password("Admin password", false)?;
    let secrets = decrypt_with_password(password.as_bytes(), &st.encrypted_key_blob)
        .map_err(|e| anyhow!("decrypt key blob (wrong password?): {e}"))?;
    let admin_sk = MlDsa65SecretKey(secrets.cluster_admin.0.clone());
    let cluster_shared_key = ClusterSharedKey(secrets.cluster_shared_key.0.clone());

    // Generate the per-invite secrets.
    let invite_nonce = random_bytes(32).map_err(|e| anyhow!("rng: {e}"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let expires_at_ms = now_ms.saturating_add(args.ttl_secs.saturating_mul(1000));

    // Build the inner payload + seal cluster_shared_key under invite_kek.
    let invite_kek = InviteKek::derive(&admin_sk, &invite_nonce)
        .map_err(|e| anyhow!("derive invite KEK: {e}"))?;
    let kek_aead: AeadKey = invite_kek.to_aead_key();
    let aad = b"vitonomi/invite_kek/v1";
    let sealed_cluster_key = seal(&kek_aead, cluster_shared_key.as_bytes(), aad)
        .map_err(|e| anyhow!("seal cluster_shared_key: {e}"))?;

    let inner = InviteInnerPayload {
        format_version: FormatVersion::V1,
        vault_role: VaultRole::Storage,
        hub_url: cfg.hub.url.clone(),
        hub_cert_fingerprint: args.hub_cert_fingerprint.clone(),
        sealed_cluster_key,
    };

    // Compute outer summary + admin signature.
    let inner_bytes = cbor_to_vec(&inner).map_err(|e| anyhow!("CBOR(inner): {e}"))?;
    let mut h = Sha256::new();
    h.update(&inner_bytes);
    let inner_payload_hash = h.finalize().to_vec();

    let mut signed = Vec::new();
    signed.push(FormatVersion::V1.as_u8());
    signed.extend_from_slice(st.cluster_id.as_bytes());
    signed.extend_from_slice(&invite_nonce);
    signed.extend_from_slice(&expires_at_ms.to_be_bytes());
    signed.extend_from_slice(&inner_payload_hash);
    let sig_admin_outer =
        ml_dsa_65_sign(&admin_sk, &signed).map_err(|e| anyhow!("sign outer: {e}"))?;

    let outer = InviteOuterSummary {
        format_version: FormatVersion::V1,
        cluster_id: st.cluster_id,
        invite_nonce: invite_nonce.clone(),
        expires_at_ms,
        inner_payload_hash,
        sig_admin_outer,
    };

    // POST the outer summary to the hub.
    let client = hub_client::default_client()?;
    let _ = hub_client::create_invite(
        &client,
        &cfg.hub.url,
        &token.0,
        &CreateInviteRequest {
            invite: outer.clone(),
        },
    )
    .await
    .context("POST /v1/vaults/invites")?;

    // Emit the combined invite token for operator transport.
    let combined = CombinedInvite { outer, inner };
    let combined_bytes = cbor_to_vec(&combined).map_err(|e| anyhow!("CBOR(combined): {e}"))?;
    let token_str = b64url_encode(&combined_bytes);

    eprintln!(
        "invite created for vault `{}` (TTL {}s)",
        args.vault_name, args.ttl_secs
    );
    eprintln!("  TRANSMIT THIS OVER A CONFIDENTIAL CHANNEL:");
    eprintln!();
    eprintln!("{token_str}");
    eprintln!();
    Ok(token_str)
}

/// Mirror of `vitonomi_vault::accept::CombinedInvite` — duplicated
/// here to avoid a dep on the vault crate. Both sides serialize the
/// same CBOR shape: `{ outer, inner }`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CombinedInvite {
    pub outer: InviteOuterSummary,
    pub inner: InviteInnerPayload,
}
