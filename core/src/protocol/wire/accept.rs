//! Vault accept-invite wire types
//! (`POST /v1/vaults/invites`, `POST /v1/vaults/accept`).

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

/// Body of an admin-signed invite token. The CBOR-encoded body is
/// what the cluster admin signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteTokenBody {
    pub format_version: FormatVersion,
    pub cluster_id: ClusterId,
    pub vault_role: VaultRole,
    pub hub_url: String,
    /// SPKI SHA-256 of the hub's TLS certificate, base64url-encoded
    /// (no padding) with a `sha256:` prefix.
    pub hub_cert_fingerprint: String,
    #[serde(with = "serde_bytes")]
    pub invite_nonce: Vec<u8>,
    pub expires_at_ms: u64,
}

/// Full invite token = body + admin signature over CBOR(body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteToken {
    pub body: InviteTokenBody,
    pub sig_cluster_admin: MlDsa65Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    pub invite: InviteToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteResponse {
    /// Echoes back the invite for confirmation; CLI can re-display.
    pub invite: InviteToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptRequest {
    pub invite: InviteToken,
    pub vault_pubkey: MlDsa65PublicKey,
    pub vault_name: String,
    /// Vault's signature over `invite_nonce || vault_pubkey_bytes`,
    /// proving possession of the secret half of `vault_pubkey`.
    pub sig_vault: MlDsa65Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptResponse {
    pub cluster_id: ClusterId,
    pub vault_id: VaultId,
    pub cluster_admin_pubkey: MlDsa65PublicKey,
    /// Snapshot of the chain head at the moment of acceptance, so
    /// the new vault has a verified anchor before connecting.
    pub chain_head: crate::crypto::admin_chain::AdminChainEntry,
}
