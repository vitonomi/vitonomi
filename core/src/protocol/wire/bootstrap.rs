//! Vault → hub auto-bootstrap. Used when a vault connects to a fresh
//! hub that has no record of the cluster (typical after a hub reboot
//! with `InMemoryHub`-backed state, or a deliberate hub migration).
//!
//! The cluster's authoritative state lives on the vaults — chain copy
//! on disk plus the admin-signed invite outer summary the vault saw
//! during accept. Bootstrap re-presents that material so the hub can
//! re-create its (cached) view of the cluster without any admin
//! intervention.
//!
//! Hub-side validation (no cluster_shared_key needed):
//!   1. `cluster_id == sha256(cluster_admin_pubkey || format_version)`
//!   2. `verify_chain_outer_only(cluster_admin_pubkey, cluster_id, chain_export)`
//!   3. `invite_outer.sig_admin_outer` verifies under `cluster_admin_pubkey`
//!   4. `invite_outer.cluster_id == cluster_id`
//!   5. `sig_vault` verifies under `vault_pubkey` over
//!      `invite_nonce || vault_pubkey_bytes`
//!   6. Operator [`BootstrapPolicy`] gate.

use serde::{Deserialize, Serialize};

use crate::crypto::admin_chain::AdminChainEntry;
use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65Signature};
use crate::protocol::wire::accept::InviteOuterSummary;
use crate::types::{ClusterId, VaultId};

/// What the operator allows on this hub. Configured at hub startup
/// and consulted by `bootstrap_cluster` after cryptographic checks
/// pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum BootstrapPolicy {
    /// Self-hosted default. The first cluster to bootstrap takes the
    /// slot; subsequent attempts for any *other* cluster_id are
    /// rejected. Re-bootstrap of the already-registered cluster is
    /// idempotent.
    SingleUser,
    /// Only the cluster_ids listed are allowed to bootstrap. Suitable
    /// for a hub hosting a small, known set of clusters.
    Allowlist { cluster_ids: Vec<ClusterId> },
    /// No policy gate — any cryptographically-valid bootstrap
    /// succeeds. Hosted infrastructure should ONLY use this if the
    /// gate has moved to an outer layer (Stripe subscription,
    /// reverse-proxy header, etc.). Not safe as a public-internet
    /// default.
    Open,
}

impl Default for BootstrapPolicy {
    fn default() -> Self {
        Self::SingleUser
    }
}

/// Vault → hub bootstrap request. Unauthenticated on the wire; gates
/// are entirely cryptographic + policy-based.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapRequest {
    pub cluster_admin_pubkey: MlDsa65PublicKey,
    pub chain_export: Vec<AdminChainEntry>,
    pub vault_pubkey: MlDsa65PublicKey,
    /// The original admin-signed invite outer summary the vault saw
    /// during its first `accept`. Persisted in the vault's enrollment
    /// file specifically for re-presentation here.
    pub invite_outer: InviteOuterSummary,
    /// The vault's signature over `invite_nonce || vault_pubkey_bytes`,
    /// constructed at original accept time. Re-used here as proof
    /// the vault holds `vault_sk` AND was bound to this invite slot.
    pub sig_vault: MlDsa65Signature,
}

/// Hub → vault bootstrap response. The hub assigns a fresh
/// `vault_id` (or returns the existing one if this vault is already
/// registered).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResponse {
    pub cluster_id: ClusterId,
    pub vault_id: VaultId,
    /// `true` when the hub created the cluster as part of this
    /// bootstrap. `false` when the cluster was already present and
    /// only the vault was added (or both were present and this was a
    /// no-op).
    pub created_cluster: bool,
    /// `true` when this vault was newly registered. `false` for an
    /// idempotent re-bootstrap of an already-known vault.
    pub created_vault: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{cbor_from_slice, cbor_to_vec};

    #[test]
    fn bootstrap_policy_serde_roundtrips() {
        for p in [
            BootstrapPolicy::SingleUser,
            BootstrapPolicy::Allowlist {
                cluster_ids: vec![],
            },
            BootstrapPolicy::Open,
        ] {
            let bytes = cbor_to_vec(&p).unwrap();
            let back: BootstrapPolicy = cbor_from_slice(&bytes).unwrap();
            assert_eq!(p, back);
        }
    }
}
