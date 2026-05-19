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
use vitonomi_core::crypto::invite_kek::{InviteKek, InviteKekSecret, SEALED_CLUSTER_KEY_AAD};
use vitonomi_core::crypto::pq::{ml_dsa_65_sign, MlDsa65SecretKey};
use vitonomi_core::crypto::random::random_bytes;
use vitonomi_core::encoding::cbor_to_vec;
use vitonomi_core::protocol::wire::accept::{
    encode_short_token, CreateInviteRequest, InviteInnerPayload, InviteOuterSummary,
    ShortInviteToken, VaultRole,
};
use vitonomi_core::types::FormatVersion;

use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::secret_cache;
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

    // Unseal master secrets via the cache (or prompt if cold).
    let state_dir = state_dir_of(args.state_path);
    let secrets = secret_cache::read_or_prompt(&st, &state_dir, prompts)?;
    let admin_sk = MlDsa65SecretKey(secrets.cluster_admin.0.clone());
    let cluster_shared_key = ClusterSharedKey(secrets.cluster_shared_key.0.clone());

    // Generate the per-invite secrets.
    let invite_nonce = random_bytes(32).map_err(|e| anyhow!("rng: {e}"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let expires_at_ms = now_ms.saturating_add(args.ttl_secs.saturating_mul(1000));

    // Build the inner payload + seal cluster_shared_key under a per-
    // invite KEK. The KEK is derived from a fresh symmetric secret +
    // the invite_nonce; the secret itself ships inside this same
    // inner payload so the vault — which never sees admin_sk — can
    // re-derive the KEK.
    let invite_kek_secret =
        InviteKekSecret::generate().map_err(|e| anyhow!("rng for invite kek secret: {e}"))?;
    let invite_kek = InviteKek::derive(&invite_kek_secret, &invite_nonce)
        .map_err(|e| anyhow!("derive invite KEK: {e}"))?;
    let kek_aead: AeadKey = invite_kek.to_aead_key();
    let sealed_cluster_key = seal(
        &kek_aead,
        cluster_shared_key.as_bytes(),
        SEALED_CLUSTER_KEY_AAD,
    )
    .map_err(|e| anyhow!("seal cluster_shared_key: {e}"))?;

    let inner = InviteInnerPayload {
        format_version: FormatVersion::V1,
        vault_role: VaultRole::Storage,
        hub_url: cfg.hub.url.clone(),
        hub_cert_fingerprint: args.hub_cert_fingerprint.clone(),
        invite_kek_secret,
        sealed_cluster_key,
    };

    // Compute outer summary + admin signature.
    let inner_bytes = cbor_to_vec(&inner).map_err(|e| anyhow!("CBOR(inner): {e}"))?;
    let mut h = Sha256::new();
    h.update(&inner_bytes);
    let inner_payload_hash = h.finalize().to_vec();

    // Two-step build: construct the unsigned outer with a placeholder
    // signature, compute the canonical signed-bytes via the public
    // helper, then attach the admin signature. Keeps the byte layout
    // in lockstep with hub + bootstrap verification paths.
    let mut outer = InviteOuterSummary {
        format_version: FormatVersion::V1,
        cluster_id: st.cluster_id,
        invite_nonce: invite_nonce.clone(),
        expires_at_ms,
        inner_payload_hash,
        sig_admin_outer: vitonomi_core::crypto::pq::MlDsa65Signature(vec![]),
    };
    let signed = vitonomi_core::protocol::wire::accept::invite_outer_signed_bytes(&outer);
    outer.sig_admin_outer =
        ml_dsa_65_sign(&admin_sk, &signed).map_err(|e| anyhow!("sign outer: {e}"))?;

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

    // Build + emit the short operator-channel token. The hub already
    // holds the full `outer` (POST'd above), so the token only needs
    // the small bag of locators + the genuinely-confidential `inner`.
    let token = ShortInviteToken {
        format_version: FormatVersion::V1,
        cluster_id: st.cluster_id,
        invite_nonce: outer.invite_nonce.clone(),
        expires_at_ms: outer.expires_at_ms,
        inner_payload_hash: outer.inner_payload_hash.clone(),
        inner,
    };
    let token_str = encode_short_token(&token).map_err(|e| anyhow!("encode token: {e}"))?;

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

fn state_dir_of(state_path: &Path) -> std::path::PathBuf {
    state_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}
