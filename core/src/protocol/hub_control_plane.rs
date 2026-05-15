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
use crate::protocol::wire::aliases::{AliasDirectoryEntry, InboundEnvelope};
use crate::protocol::wire::bootstrap::{BootstrapRequest, BootstrapResponse};
use crate::protocol::wire::domains::{
    DomainChallenge, DomainRecord, DomainVerified,
};
use crate::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, UserLookupId,
};
use crate::protocol::wire::relay_push::{
    RegisterRelayRequest, RegisterRelayResponse, RelayId, RelayPushAck, SignedRelayPush,
};
use crate::protocol::wire::subdomains::SubdomainDirectoryEntry;
use crate::record::RecordId;
use crate::types::subdomain::{Subdomain, SubdomainClaim};
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
    /// libp2p multiaddrs the vault has advertised over the vault-bus
    /// (data-plane slice 3+). Empty before the vault publishes any.
    /// Most-recent advertisement replaces the previous set; the hub
    /// does NOT merge.
    #[serde(default)]
    pub multiaddrs: Vec<String>,
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

    /// Auto-bootstrap a cluster + vault from a vault that already
    /// holds the chain copy + admin-signed invite outer. Idempotent:
    /// if the cluster (and vault) is already registered, returns the
    /// existing `vault_id` without mutating state. See
    /// [`super::wire::bootstrap`] for the validation contract.
    async fn bootstrap_cluster(
        &self,
        req: BootstrapRequest,
    ) -> Result<BootstrapResponse, CoreError>;

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

    /// Look up a vault's public key by `vault_id`. Used by the
    /// vault-bus WebSocket handshake to verify the vault's signed
    /// challenge response.
    async fn get_vault_pubkey(
        &self,
        vault_id: &VaultId,
    ) -> Result<crate::crypto::pq::MlDsa65PublicKey, CoreError>;

    /// Update a vault's `last_seen` timestamp on every signed
    /// heartbeat received via the vault-bus.
    async fn touch_vault_last_seen(&self, vault_id: &VaultId, ts_ms: u64) -> Result<(), CoreError>;

    /// Look up the latest admin-chain head for the cluster owning
    /// `vault_id`. Used by the WebSocket vault-bus handshake to
    /// populate `SessionEstablished.chain_head` without requiring
    /// the vault to first authenticate via a session token.
    async fn get_chain_head_for_vault(
        &self,
        vault_id: &VaultId,
    ) -> Result<AdminChainEntry, CoreError>;

    /// Replace a vault's advertised libp2p multiaddrs. Called by the
    /// hub's WS vault-bus handler when an authenticated vault sends
    /// an [`crate::protocol::wire::vault_bus::AdvertiseAddrsFrame`].
    /// Empty input clears the address set.
    async fn update_vault_multiaddrs(
        &self,
        vault_id: &VaultId,
        multiaddrs: Vec<String>,
    ) -> Result<(), CoreError>;

    /// Look up a user's ML-DSA-65 identity pubkey by `(cluster_id,
    /// user_id)`. Used by vaults to verify per-request signatures
    /// on `/vitonomi/chunks/1.0.0`.
    async fn get_user_identity_pubkey(
        &self,
        cluster_id: &ClusterId,
        user_id: &crate::types::UserId,
    ) -> Result<crate::crypto::pq::MlDsa65PublicKey, CoreError>;

    // ── Phase 7: subdomains (managed-base namespaces) ──────────

    /// Claim a subdomain under a managed base domain. Server-
    /// side admission gate enforces format / reserved-list /
    /// taken / one-claim-per-cluster-per-base / signature.
    /// **Does not** check `subdomain == username` — that
    /// invariant lives client-side per the Phase 7 design
    /// (see `docs/threat-model.md#relaxed_posture.client_side_username_check_only`).
    async fn claim_subdomain(
        &self,
        session_token: &SessionToken,
        claim: SubdomainClaim,
    ) -> Result<(), CoreError>;

    /// Release a previously-claimed subdomain. Tombstones the
    /// (base, sub) pair so it can't be re-claimed by a
    /// different user. Aliases under the namespace stop
    /// resolving but the per-alias inbound queues remain so
    /// the user can still drain pending mail.
    async fn release_subdomain(
        &self,
        session_token: &SessionToken,
        base_domain: &str,
        subdomain: &Subdomain,
    ) -> Result<(), CoreError>;

    /// Public lookup. Anyone can resolve `(base, subdomain) →
    /// user identity pubkey + alias-directory pointer`.
    async fn lookup_subdomain(
        &self,
        base_domain: &str,
        subdomain: &Subdomain,
    ) -> Result<SubdomainDirectoryEntry, CoreError>;

    /// Public list of base domains the hub allows subdomain
    /// claims under (`["vito.gg"]` for hosted vitonomi).
    async fn list_managed_base_domains(&self) -> Result<Vec<String>, CoreError>;

    // ── Phase 7: custom domains (DNS-verify) ───────────────────

    async fn add_custom_domain(
        &self,
        session_token: &SessionToken,
        domain: &str,
    ) -> Result<DomainChallenge, CoreError>;

    async fn verify_custom_domain(
        &self,
        session_token: &SessionToken,
        domain: &str,
    ) -> Result<DomainVerified, CoreError>;

    async fn list_custom_domains(
        &self,
        session_token: &SessionToken,
    ) -> Result<Vec<DomainRecord>, CoreError>;

    async fn remove_custom_domain(
        &self,
        session_token: &SessionToken,
        domain: &str,
    ) -> Result<(), CoreError>;

    // ── Phase 7: alias directory (public read, signed write) ───

    async fn publish_alias_pubkey(
        &self,
        session_token: &SessionToken,
        entry: AliasDirectoryEntry,
    ) -> Result<(), CoreError>;

    async fn lookup_alias_pubkey(
        &self,
        alias_handle: &str,
        namespace: &str,
    ) -> Result<AliasDirectoryEntry, CoreError>;

    async fn revoke_alias_pubkey(
        &self,
        session_token: &SessionToken,
        alias_handle: &str,
        namespace: &str,
    ) -> Result<(), CoreError>;

    // ── Phase 7: per-alias inbound queue (shape A) ─────────────

    /// Push a relay-side encrypted envelope into the addressee's
    /// per-alias FIFO. Hub verifies `sig_relay` against the
    /// registered relay pubkey; on unknown alias returns a
    /// silent-drop ack (`RelayPushAck { received: false }`)
    /// without logging the address.
    async fn relay_push_inbound(
        &self,
        push: SignedRelayPush,
    ) -> Result<RelayPushAck, CoreError>;

    /// Authenticated fetch of envelopes since `since_seq`
    /// (exclusive). Empty result if no new mail.
    async fn fetch_alias_inbox(
        &self,
        session_token: &SessionToken,
        alias_id: &RecordId,
        since_seq: u64,
    ) -> Result<Vec<InboundEnvelope>, CoreError>;

    /// Acknowledge envelopes up to and including `up_to_seq`.
    /// Hub may garbage-collect ack'd envelopes on its own
    /// schedule; the contract is "client has merged up to
    /// here, you can drop them whenever".
    async fn ack_alias_inbox(
        &self,
        session_token: &SessionToken,
        alias_id: &RecordId,
        up_to_seq: u64,
    ) -> Result<(), CoreError>;

    // ── Phase 7: relay identity registration ───────────────────

    /// Operator-only. Registers a relay's ML-DSA-65 pubkey so
    /// the hub will accept its [`relay_push_inbound`] calls.
    /// Restricted to admin sessions in production; the
    /// in-memory backend currently allows any session.
    async fn register_relay_identity(
        &self,
        session_token: &SessionToken,
        req: RegisterRelayRequest,
    ) -> Result<RegisterRelayResponse, CoreError>;

    async fn lookup_relay_pubkey(
        &self,
        relay_id: &RelayId,
    ) -> Result<crate::crypto::pq::MlDsa65PublicKey, CoreError>;
}
