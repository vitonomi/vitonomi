//! Vault accept-invite wire types (hub-blind redesign).
//!
//! - [`InviteOuterSummary`] — the only part the hub stores. Carries
//!   `cluster_id`, `invite_nonce`, `expires_at_ms`,
//!   `inner_payload_hash`, and the outer admin signature. Hub
//!   verifies signature against the cluster admin pubkey to gate
//!   admission.
//! - [`InviteInnerPayload`] — out-of-band only. Transmitted from
//!   admin to vault operator (typically embedded in the invite
//!   string the operator pastes). Carries `vault_role`, `hub_url`,
//!   `hub_cert_fingerprint`, and the AEAD-sealed
//!   `cluster_shared_key` (sealed under the per-invite KEK; see
//!   `crate::crypto::invite_kek`).

use serde::{Deserialize, Serialize};

use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65Signature};
use crate::types::{ClusterId, FormatVersion, VaultId};

/// Roles a vault can hold within a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultRole {
    /// Storage vault (default — holds chunks, runs replication).
    Storage,
}

/// What the hub stores for a registered invite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteOuterSummary {
    pub format_version: FormatVersion,
    pub cluster_id: ClusterId,
    #[serde(with = "serde_bytes")]
    pub invite_nonce: Vec<u8>,
    pub expires_at_ms: u64,
    /// SHA-256 of CBOR-encoded [`InviteInnerPayload`]. Hub verifies
    /// the vault's submitted inner payload matches this hash.
    #[serde(with = "serde_bytes")]
    pub inner_payload_hash: Vec<u8>,
    pub sig_admin_outer: MlDsa65Signature,
}

/// Out-of-band only. Carries everything the hub MUST NOT see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteInnerPayload {
    pub format_version: FormatVersion,
    pub vault_role: VaultRole,
    pub hub_url: String,
    /// `sha256:<base64url-no-padding>` SPKI hash of the hub TLS leaf cert.
    pub hub_cert_fingerprint: String,
    /// `nonce(24) || aead_ct(cluster_shared_key:32 + tag:16)` sealed
    /// under [`crate::crypto::invite_kek::InviteKek`].
    #[serde(with = "serde_bytes")]
    pub sealed_cluster_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    pub invite: InviteOuterSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteResponse {
    pub invite: InviteOuterSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptRequest {
    pub invite_outer: InviteOuterSummary,
    pub invite_inner: InviteInnerPayload,
    pub vault_pubkey: MlDsa65PublicKey,
    /// Vault's signature over `invite_nonce || vault_pubkey_bytes`,
    /// proving possession of the secret half of `vault_pubkey`.
    pub sig_vault: MlDsa65Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptResponse {
    pub cluster_id: ClusterId,
    pub vault_id: VaultId,
    pub cluster_admin_pubkey: MlDsa65PublicKey,
    /// Outer envelope of the latest admin chain entry the hub knows
    /// about. The vault verifies its signature against
    /// `cluster_admin_pubkey` and unseals locally.
    pub chain_head: crate::crypto::admin_chain::AdminChainEntry,
}
