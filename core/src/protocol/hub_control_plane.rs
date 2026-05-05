//! Trait abstraction over the hub's HTTP control-plane surface.
//!
//! Implementations:
//! - `HostedHubClient` (in the `clients/cli` and PWA crates) — real
//!   HTTP/TLS via `reqwest`.
//! - `InMemoryHubControlPlane` (in [`super::testing`]) — in-process
//!   double for integration tests.
//!
//! Whatever the transport, every method here MUST operate on the
//! exact same wire types so the two implementations are
//! interchangeable.

use async_trait::async_trait;

use crate::crypto::admin_chain::AdminChainEntry;
use crate::crypto::keys::MasterPublicKeys;
use crate::errors::CoreError;
use crate::protocol::wire::accept::{
    AcceptRequest, AcceptResponse, CreateInviteRequest, CreateInviteResponse,
};
use crate::protocol::wire::admin_chain::ChainExport;
use crate::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, UserLookupId,
};
use crate::types::{ClusterId, SessionToken, VaultId};

/// Cluster-register request — hub-blind. The hub stores users keyed
/// by `lookup_id` (Argon2id + cluster_pepper); raw username is never
/// transmitted. `encrypted_key_blob` is opaque to the hub; its
/// plaintext header carries `auth_salt`, `enc_salt`, and Argon2id
/// parameters needed by the client to decrypt locally.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterRegisterRequest {
    pub lookup_id: UserLookupId,
    pub master_pubkeys: MasterPublicKeys,
    /// CBOR-encoded encrypted key blob (opaque to hub).
    #[serde(with = "serde_bytes")]
    pub encrypted_key_blob: Vec<u8>,
    pub genesis_entry: AdminChainEntry,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterRegisterResponse {
    pub cluster_id: ClusterId,
    pub user_id: crate::types::UserId,
    pub session_token: SessionToken,
    pub session_expires_at_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClusterRestoreRequest {
    pub lookup_id: UserLookupId,
    pub master_pubkeys: MasterPublicKeys,
    #[serde(with = "serde_bytes")]
    pub encrypted_key_blob: Vec<u8>,
    pub chain_export: ChainExport,
}

/// Hub-readable vault record. Plaintext fields are restricted to the
/// hub-blindness allow-list: opaque ids, public key, connection-
/// observable state. Vault names + roles are sealed under the
/// cluster shared key in `sealed_meta`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultRecord {
    pub vault_id: VaultId,
    pub vault_pubkey: crate::crypto::pq::MlDsa65PublicKey,
    pub last_seen_ms: Option<u64>,
    pub status: VaultStatus,
    /// AEAD ciphertext under cluster shared key. Holds vault_name,
    /// vault_role, enrollment_ts, etc. Hub stores opaque bytes.
    #[serde(with = "serde_bytes")]
    pub sealed_meta: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VaultStatus {
    Online,
    Offline,
    Revoked,
}

#[async_trait]
pub trait HubControlPlane: Send + Sync {
    /// Register a new cluster (cluster admin user) on this hub.
    async fn register_cluster(
        &self,
        req: ClusterRegisterRequest,
    ) -> Result<ClusterRegisterResponse, CoreError>;

    /// Restore an existing cluster onto this hub from a chain export.
    async fn restore_cluster(
        &self,
        req: ClusterRestoreRequest,
    ) -> Result<ClusterRegisterResponse, CoreError>;

    /// Begin a login flow.
    async fn login_start(&self, req: LoginStartRequest) -> Result<LoginStartResponse, CoreError>;

    /// Finish a login flow with a signed challenge.
    async fn login_finish(&self, req: LoginFinishRequest)
        -> Result<LoginFinishResponse, CoreError>;

    /// End the current session.
    async fn logout(&self, session_token: &SessionToken) -> Result<(), CoreError>;

    /// Fetch the active session's encrypted key blob.
    async fn get_keyblob(&self, session_token: &SessionToken) -> Result<Vec<u8>, CoreError>;

    /// Replace the active session's encrypted key blob.
    async fn put_keyblob(
        &self,
        session_token: &SessionToken,
        encrypted_key_blob: Vec<u8>,
    ) -> Result<(), CoreError>;

    /// List all vaults in the active user's cluster.
    async fn list_vaults(
        &self,
        session_token: &SessionToken,
    ) -> Result<Vec<VaultRecord>, CoreError>;

    /// Admin-only: register an admin-signed vault invite token.
    async fn create_vault_invite(
        &self,
        session_token: &SessionToken,
        req: CreateInviteRequest,
    ) -> Result<CreateInviteResponse, CoreError>;

    /// Vault-side: accept an invite and register the vault.
    async fn accept_vault_invite(&self, req: AcceptRequest) -> Result<AcceptResponse, CoreError>;

    /// Get the latest admin chain head for a cluster.
    async fn get_admin_chain_head(
        &self,
        session_token: &SessionToken,
        cluster_id: &ClusterId,
    ) -> Result<AdminChainEntry, CoreError>;

    /// Get a paginated slice of the admin chain (`from_seq` inclusive).
    async fn get_admin_chain(
        &self,
        session_token: &SessionToken,
        cluster_id: &ClusterId,
        from_seq: u64,
    ) -> Result<Vec<AdminChainEntry>, CoreError>;

    /// Append a batch of admin chain entries (used during restore + catch-up).
    async fn append_admin_chain(
        &self,
        session_token: &SessionToken,
        cluster_id: &ClusterId,
        entries: Vec<AdminChainEntry>,
    ) -> Result<(), CoreError>;
}
