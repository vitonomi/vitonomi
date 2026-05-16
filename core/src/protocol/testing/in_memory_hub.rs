//! In-memory `HubControlPlane` implementation for integration tests
//! under the hub-blindness invariant.
//!
//! Stores only the allow-listed plaintext fields: `cluster_id`,
//! public keys, opaque ids, connection-observable state, and signed
//! envelope shells with sealed bodies. Verifies admin signatures
//! (outer envelope) and vault signatures at the relevant gates.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use sha2::Digest as _;

use crate::crypto::admin_chain::{verify_outer, AdminChainEntry, GENESIS_PREV_HASH};
use crate::crypto::challenge::{verify_challenge, Challenge};
use crate::crypto::cluster::cluster_id_of;
use crate::crypto::pq::MlDsa65PublicKey;
use crate::crypto::random::random_bytes;
use crate::encoding::{b64url_encode, cbor_to_vec};
use crate::errors::{AuthError, CoreError, CryptoError};
use crate::crypto::pq::ml_dsa_65_verify;
use crate::protocol::hub_control_plane::{
    ClusterRegisterRequest, ClusterRegisterResponse, ClusterRestoreRequest, HubControlPlane,
    VaultRecord, VaultStatus,
};
use crate::protocol::wire::accept::{
    invite_outer_signed_bytes, AcceptRequest, AcceptResponse, CreateInviteRequest,
    CreateInviteResponse,
};
use crate::protocol::wire::aliases::{AliasDirectoryEntry, InboundEnvelope};
use crate::protocol::wire::bootstrap::{BootstrapPolicy, BootstrapRequest, BootstrapResponse};
use crate::protocol::wire::domains::{
    DomainChallenge, DomainRecord, DomainStatus, DomainVerified,
};
use crate::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
};
use crate::protocol::wire::mx_relay_push::{
    MxRelayId, MxRelayPushAck, RegisterMxRelayRequest, SignedMxRelayPush,
};
use crate::protocol::wire::subdomains::SubdomainDirectoryEntry;
use crate::record::RecordId;
use crate::types::subdomain::{is_reserved_subdomain, Subdomain, SubdomainClaim};
use crate::types::{ClusterId, FormatVersion, SessionToken, UserId, VaultId};

#[derive(Default)]
struct HubState {
    clusters: HashMap<ClusterId, ClusterRecord>,
    users_by_lookup: HashMap<Vec<u8>, UserRecord>,
    sessions: HashMap<String, Session>,
    challenges: HashMap<String, PendingChallenge>,
    invite_used: HashMap<Vec<u8>, ()>,
    /// Open invites — keyed by `invite_nonce`, value is the stored
    /// outer summary. Hub uses these for replay defense + admission.
    invite_outers: HashMap<Vec<u8>, crate::protocol::wire::accept::InviteOuterSummary>,
    // ── Subdomains, domains, aliases, mx-relays ────────────────
    /// `(base_domain, subdomain) → claim record + owner`.
    /// Tombstoned subdomains live in `tombstoned_subdomains`.
    subdomains: HashMap<(String, Subdomain), SubdomainSlot>,
    tombstoned_subdomains: HashMap<(String, Subdomain), u64>,
    /// `(user_id, domain) → DNS-verified domain record`.
    domains: HashMap<(UserId, String), DomainSlot>,
    /// `(alias_handle, namespace) → AliasDirectoryEntry`.
    alias_directory: HashMap<(String, String), AliasDirectoryEntry>,
    /// `mx_relay_id → registration`.
    mx_relay_pubkeys: HashMap<MxRelayId, MxRelayRegistration>,
    /// Per-alias monotonic FIFO of inbound envelopes.
    inbound_queues: HashMap<RecordId, Vec<InboundEnvelope>>,
    /// Per-alias high-water mark — the seq the client has acked.
    inbox_acks: HashMap<RecordId, u64>,
    /// Per-alias monotonic seq counter, incremented on each push.
    inbox_seq_counters: HashMap<RecordId, u64>,
}

struct SubdomainSlot {
    user_id: UserId,
    cluster_id: ClusterId,
    claim: SubdomainClaim,
    claimed_at_ms: u64,
}

struct DomainSlot {
    status: DomainStatus,
    challenge: [u8; 32],
    verified_at_ms: Option<u64>,
}

struct MxRelayRegistration {
    pubkey: MlDsa65PublicKey,
    allowed_namespaces: Vec<String>,
}

struct ClusterRecord {
    admin_pubkey: MlDsa65PublicKey,
    chain: Vec<AdminChainEntry>,
    vaults: Vec<VaultRecord>,
}

struct UserRecord {
    user_id: UserId,
    cluster_id: ClusterId,
    identity_pubkey: MlDsa65PublicKey,
    encrypted_key_blob: Vec<u8>,
}

struct Session {
    user_id: UserId,
    cluster_id: ClusterId,
    expires_at_ms: u64,
}

struct PendingChallenge {
    user_id: UserId,
    challenge: Challenge,
    expires_at_ms: u64,
}

/// In-memory hub for integration tests.
pub struct InMemoryHubControlPlane {
    state: Mutex<HubState>,
    clock_ms: fn() -> u64,
    bootstrap_policy: BootstrapPolicy,
}

impl InMemoryHubControlPlane {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HubState::default()),
            clock_ms: default_clock_ms,
            bootstrap_policy: BootstrapPolicy::default(),
        }
    }

    #[must_use]
    pub fn with_clock(clock_ms: fn() -> u64) -> Self {
        Self {
            state: Mutex::new(HubState::default()),
            clock_ms,
            bootstrap_policy: BootstrapPolicy::default(),
        }
    }

    /// Override the operator's bootstrap admission policy. Default is
    /// [`BootstrapPolicy::SingleUser`].
    #[must_use]
    pub fn with_bootstrap_policy(mut self, policy: BootstrapPolicy) -> Self {
        self.bootstrap_policy = policy;
        self
    }

    fn now(&self) -> u64 {
        (self.clock_ms)()
    }

    fn issue_session(
        &self,
        state: &mut HubState,
        user_id: UserId,
        cluster_id: ClusterId,
    ) -> (SessionToken, u64) {
        let raw = b64url_encode(&random_bytes(32).expect("rng"));
        let expires_at_ms = self.now() + 60 * 60 * 1000;
        state.sessions.insert(
            raw.clone(),
            Session {
                user_id,
                cluster_id,
                expires_at_ms,
            },
        );
        (SessionToken(raw), expires_at_ms)
    }

    fn lookup_session<'s>(
        &self,
        state: &'s HubState,
        token: &SessionToken,
    ) -> Result<&'s Session, CoreError> {
        let s = state
            .sessions
            .get(&token.0)
            .ok_or_else(|| CoreError::Auth(AuthError::SessionUnknown))?;
        if s.expires_at_ms < self.now() {
            return Err(CoreError::Auth(AuthError::SessionExpired));
        }
        Ok(s)
    }
}

impl Default for InMemoryHubControlPlane {
    fn default() -> Self {
        Self::new()
    }
}

fn default_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[async_trait]
impl HubControlPlane for InMemoryHubControlPlane {
    async fn register_cluster(
        &self,
        req: ClusterRegisterRequest,
    ) -> Result<ClusterRegisterResponse, CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let cluster_id = cluster_id_of(&req.master_pubkeys.cluster_admin, FormatVersion::V1);
        if state.clusters.contains_key(&cluster_id) {
            return Err(CoreError::Auth(AuthError::Forbidden));
        }
        if state.users_by_lookup.contains_key(req.lookup_id.as_bytes()) {
            return Err(CoreError::Auth(AuthError::Forbidden));
        }

        // Verify genesis entry's outer signature against admin pubkey.
        verify_outer(&req.master_pubkeys.cluster_admin, &req.genesis_entry)?;
        if req.genesis_entry.cluster_id != cluster_id
            || req.genesis_entry.seq != 0
            || req.genesis_entry.prev_hash != GENESIS_PREV_HASH
        {
            return Err(CoreError::Crypto(CryptoError::AdminChain(
                "genesis entry mismatched cluster_id / seq / prev_hash".into(),
            )));
        }

        let user_id = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&random_bytes(16).expect("rng"));
            UserId(buf)
        };

        state.clusters.insert(
            cluster_id,
            ClusterRecord {
                admin_pubkey: req.master_pubkeys.cluster_admin.clone(),
                chain: vec![req.genesis_entry.clone()],
                vaults: vec![],
            },
        );
        state.users_by_lookup.insert(
            req.lookup_id.0.clone(),
            UserRecord {
                user_id,
                cluster_id,
                identity_pubkey: req.master_pubkeys.identity.clone(),
                encrypted_key_blob: req.encrypted_key_blob,
            },
        );
        let (session_token, session_expires_at_ms) =
            self.issue_session(&mut state, user_id, cluster_id);
        Ok(ClusterRegisterResponse {
            cluster_id,
            user_id,
            session_token,
            session_expires_at_ms,
        })
    }

    async fn restore_cluster(
        &self,
        req: ClusterRestoreRequest,
    ) -> Result<ClusterRegisterResponse, CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let cluster_id = req.chain_export.cluster_id;
        if state.clusters.contains_key(&cluster_id) {
            return Err(CoreError::Auth(AuthError::Forbidden));
        }
        // Outer-only chain verify (hub doesn't have cluster_shared_key).
        crate::crypto::admin_chain::verify_chain_outer_only(
            &req.master_pubkeys.cluster_admin,
            cluster_id,
            &req.chain_export.entries,
        )?;
        if cluster_id_of(&req.master_pubkeys.cluster_admin, FormatVersion::V1) != cluster_id {
            return Err(CoreError::Crypto(CryptoError::AdminChain(
                "cluster_id does not match cluster_admin pubkey".into(),
            )));
        }
        let user_id = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&random_bytes(16).expect("rng"));
            UserId(buf)
        };
        state.clusters.insert(
            cluster_id,
            ClusterRecord {
                admin_pubkey: req.master_pubkeys.cluster_admin.clone(),
                chain: req.chain_export.entries.clone(),
                vaults: vec![],
            },
        );
        state.users_by_lookup.insert(
            req.lookup_id.0.clone(),
            UserRecord {
                user_id,
                cluster_id,
                identity_pubkey: req.master_pubkeys.identity.clone(),
                encrypted_key_blob: req.encrypted_key_blob,
            },
        );
        let (session_token, session_expires_at_ms) =
            self.issue_session(&mut state, user_id, cluster_id);
        Ok(ClusterRegisterResponse {
            cluster_id,
            user_id,
            session_token,
            session_expires_at_ms,
        })
    }

    async fn bootstrap_cluster(
        &self,
        req: BootstrapRequest,
    ) -> Result<BootstrapResponse, CoreError> {
        // 1. Cluster identity is bound to the admin pubkey.
        let cluster_id = cluster_id_of(&req.cluster_admin_pubkey, FormatVersion::V1);

        // 2. Chain integrity (outer-only — no cluster_shared_key).
        if req.chain_export.is_empty() {
            return Err(CoreError::Crypto(CryptoError::AdminChain(
                "bootstrap chain_export is empty".into(),
            )));
        }
        crate::crypto::admin_chain::verify_chain_outer_only(
            &req.cluster_admin_pubkey,
            cluster_id,
            &req.chain_export,
        )?;
        // Genesis sanity (verify_chain_outer_only checks linkage but
        // not seq/prev_hash on the head).
        let genesis = &req.chain_export[0];
        if genesis.seq != 0 || genesis.prev_hash != GENESIS_PREV_HASH {
            return Err(CoreError::Crypto(CryptoError::AdminChain(
                "genesis seq / prev_hash invalid".into(),
            )));
        }

        // 3. Admin signature on the membership-bearing invite outer.
        let body_bytes = invite_outer_signed_bytes(&req.invite_outer);
        crate::crypto::pq::ml_dsa_65_verify(
            &req.cluster_admin_pubkey,
            &req.invite_outer.sig_admin_outer,
            &body_bytes,
        )?;
        if req.invite_outer.cluster_id != cluster_id {
            return Err(CoreError::Crypto(CryptoError::AdminChain(
                "invite cluster_id != bootstrap cluster_id".into(),
            )));
        }

        // 4. Vault sig over (invite_nonce || vault_pubkey_bytes).
        let mut signed = Vec::with_capacity(
            req.invite_outer.invite_nonce.len() + req.vault_pubkey.as_bytes().len(),
        );
        signed.extend_from_slice(&req.invite_outer.invite_nonce);
        signed.extend_from_slice(req.vault_pubkey.as_bytes());
        crate::crypto::pq::ml_dsa_65_verify(&req.vault_pubkey, &req.sig_vault, &signed)?;

        // 5. Operator policy gate. Single-user mode rejects any
        //    *other* cluster_id but allows idempotent re-bootstrap of
        //    the already-registered cluster.
        let mut state = self.state.lock().expect("poisoned");
        match &self.bootstrap_policy {
            BootstrapPolicy::SingleUser => {
                if let Some((existing_id, _)) = state.clusters.iter().next() {
                    if *existing_id != cluster_id {
                        return Err(CoreError::Auth(AuthError::Forbidden));
                    }
                }
            }
            BootstrapPolicy::Allowlist { cluster_ids } => {
                if !cluster_ids.iter().any(|c| *c == cluster_id) {
                    return Err(CoreError::Auth(AuthError::Forbidden));
                }
            }
            BootstrapPolicy::Open => {}
        }

        // 6. Idempotent register. Cluster + chain are created if
        //    absent; vault is registered if absent.
        let created_cluster = !state.clusters.contains_key(&cluster_id);
        if created_cluster {
            state.clusters.insert(
                cluster_id,
                ClusterRecord {
                    admin_pubkey: req.cluster_admin_pubkey.clone(),
                    chain: req.chain_export.clone(),
                    vaults: vec![],
                },
            );
        } else {
            // Refuse if the existing cluster is registered under a
            // different admin pubkey — protects against cluster_id
            // collisions (which would imply pubkey reuse, but
            // defense-in-depth).
            let existing = state
                .clusters
                .get(&cluster_id)
                .expect("contains_key just checked");
            if existing.admin_pubkey != req.cluster_admin_pubkey {
                return Err(CoreError::Auth(AuthError::Forbidden));
            }
        }

        let cluster = state
            .clusters
            .get_mut(&cluster_id)
            .expect("just inserted or already present");
        let existing_vault_id = cluster
            .vaults
            .iter()
            .find(|v| v.vault_pubkey == req.vault_pubkey)
            .map(|v| v.vault_id);
        let (vault_id, created_vault) = match existing_vault_id {
            Some(id) => (id, false),
            None => {
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&random_bytes(16).expect("rng"));
                let vault_id = VaultId(buf);
                cluster.vaults.push(VaultRecord {
                    vault_id,
                    vault_pubkey: req.vault_pubkey.clone(),
                    last_seen_ms: None,
                    status: VaultStatus::Online,
                    sealed_meta: vec![],
                    multiaddrs: vec![],
                });
                (vault_id, true)
            }
        };

        Ok(BootstrapResponse {
            cluster_id,
            vault_id,
            created_cluster,
            created_vault,
        })
    }

    async fn login_start(&self, req: LoginStartRequest) -> Result<LoginStartResponse, CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let snapshot = {
            let user = state
                .users_by_lookup
                .get(req.lookup_id.as_bytes())
                .ok_or_else(|| CoreError::Auth(AuthError::InvalidCredentials))?;
            UserSnapshot {
                user_id: user.user_id,
                encrypted_key_blob: user.encrypted_key_blob.clone(),
            }
        };

        let challenge = Challenge::generate(self.now())?;
        let challenge_id = b64url_encode(&random_bytes(16).expect("rng"));
        let expires_at_ms = self.now() + 5 * 60 * 1000;

        let resp = LoginStartResponse {
            encrypted_key_blob: snapshot.encrypted_key_blob,
            challenge: challenge.clone(),
            challenge_id: challenge_id.clone(),
            expires_at_ms,
        };

        state.challenges.insert(
            challenge_id,
            PendingChallenge {
                user_id: snapshot.user_id,
                challenge,
                expires_at_ms,
            },
        );
        Ok(resp)
    }

    async fn login_finish(
        &self,
        req: LoginFinishRequest,
    ) -> Result<LoginFinishResponse, CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let pending = state
            .challenges
            .remove(&req.challenge_id)
            .ok_or_else(|| CoreError::Auth(AuthError::ChallengeExpired))?;
        if pending.expires_at_ms < self.now() {
            return Err(CoreError::Auth(AuthError::ChallengeExpired));
        }
        let user = state
            .users_by_lookup
            .values()
            .find(|u| u.user_id == pending.user_id)
            .ok_or_else(|| CoreError::Auth(AuthError::SessionUnknown))?;
        verify_challenge(&user.identity_pubkey, &pending.challenge, &req.signature)?;
        let cluster_id = user.cluster_id;
        let user_id = user.user_id;
        let (session_token, session_expires_at_ms) =
            self.issue_session(&mut state, user_id, cluster_id);
        Ok(LoginFinishResponse {
            session_token,
            session_expires_at_ms,
        })
    }

    async fn logout(&self, session_token: &SessionToken) -> Result<(), CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        state.sessions.remove(&session_token.0);
        Ok(())
    }

    async fn get_keyblob(&self, session_token: &SessionToken) -> Result<Vec<u8>, CoreError> {
        let state = self.state.lock().expect("poisoned");
        let s = self.lookup_session(&state, session_token)?;
        let user = state
            .users_by_lookup
            .values()
            .find(|u| u.user_id == s.user_id)
            .ok_or_else(|| CoreError::Auth(AuthError::SessionUnknown))?;
        Ok(user.encrypted_key_blob.clone())
    }

    async fn put_keyblob(
        &self,
        session_token: &SessionToken,
        encrypted_key_blob: Vec<u8>,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let user_id = self.lookup_session(&state, session_token)?.user_id;
        let user = state
            .users_by_lookup
            .values_mut()
            .find(|u| u.user_id == user_id)
            .ok_or_else(|| CoreError::Auth(AuthError::SessionUnknown))?;
        user.encrypted_key_blob = encrypted_key_blob;
        Ok(())
    }

    async fn list_vaults(
        &self,
        session_token: &SessionToken,
    ) -> Result<Vec<VaultRecord>, CoreError> {
        let state = self.state.lock().expect("poisoned");
        let cluster_id = self.lookup_session(&state, session_token)?.cluster_id;
        let cluster = state
            .clusters
            .get(&cluster_id)
            .ok_or_else(|| CoreError::Auth(AuthError::SessionUnknown))?;
        // Derive each vault's status at read time. The stored
        // `status` is preserved only for `Revoked`; `Online` vs
        // `Offline` is computed from `last_seen_ms` + the
        // `idle_timeout_secs` window, so a vault that crashes / is
        // killed flips to `Offline` automatically once its
        // heartbeat goes stale. Without this, the static `Online`
        // set at registration would never flip.
        let now = self.now();
        let idle_ms = crate::protocol::wire::vault_bus::idle_timeout_secs() * 1_000;
        Ok(cluster
            .vaults
            .iter()
            .map(|v| {
                let mut clone = v.clone();
                if clone.status != VaultStatus::Revoked {
                    clone.status = match clone.last_seen_ms {
                        Some(ts) if now.saturating_sub(ts) <= idle_ms => VaultStatus::Online,
                        _ => VaultStatus::Offline,
                    };
                }
                clone
            })
            .collect())
    }

    async fn create_vault_invite(
        &self,
        session_token: &SessionToken,
        req: CreateInviteRequest,
    ) -> Result<CreateInviteResponse, CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let cluster_id = self.lookup_session(&state, session_token)?.cluster_id;
        let admin_pubkey = state
            .clusters
            .get(&cluster_id)
            .ok_or_else(|| CoreError::Auth(AuthError::SessionUnknown))?
            .admin_pubkey
            .clone();
        // Verify outer signature against the cluster admin pubkey.
        let body_bytes = invite_outer_signed_bytes(&req.invite);
        crate::crypto::pq::ml_dsa_65_verify(
            &admin_pubkey,
            &req.invite.sig_admin_outer,
            &body_bytes,
        )?;
        if req.invite.cluster_id != cluster_id {
            return Err(CoreError::Crypto(CryptoError::AdminChain(
                "invite cluster_id mismatch".into(),
            )));
        }
        // Atomic dedup: reject if nonce already present.
        if state.invite_outers.contains_key(&req.invite.invite_nonce) {
            return Err(CoreError::Auth(AuthError::InviteUsedOrExpired));
        }
        state
            .invite_outers
            .insert(req.invite.invite_nonce.clone(), req.invite.clone());
        Ok(CreateInviteResponse { invite: req.invite })
    }

    async fn accept_vault_invite(&self, req: AcceptRequest) -> Result<AcceptResponse, CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let cluster_id = req.cluster_id;
        let nonce = req.invite_nonce.clone();

        // 1. Look up the hub's stored outer (admin-signed at create time).
        let stored = state
            .invite_outers
            .get(&nonce)
            .cloned()
            .ok_or(CoreError::Auth(AuthError::InviteUsedOrExpired))?;
        // 2. Outer must belong to the requested cluster.
        if stored.cluster_id != cluster_id {
            return Err(CoreError::Auth(AuthError::InviteUsedOrExpired));
        }
        // 3. Expiry + replay checks against stored outer.
        if stored.expires_at_ms < self.now() {
            return Err(CoreError::Auth(AuthError::InviteUsedOrExpired));
        }
        if state.invite_used.contains_key(&nonce) {
            return Err(CoreError::Auth(AuthError::InviteUsedOrExpired));
        }

        // 4. Snapshot admin pubkey + chain head while holding only an
        //    immutable cluster borrow.
        let (admin_pubkey, chain_head) = {
            let cluster = state
                .clusters
                .get(&cluster_id)
                .ok_or_else(|| CoreError::Auth(AuthError::Forbidden))?;
            let head =
                cluster.chain.last().cloned().ok_or_else(|| {
                    CoreError::Crypto(CryptoError::AdminChain("empty chain".into()))
                })?;
            (cluster.admin_pubkey.clone(), head)
        };

        // 5. Re-verify the admin signature on the stored outer (defense
        //    in depth — the outer was already verified at create time).
        let body_bytes = invite_outer_signed_bytes(&stored);
        crate::crypto::pq::ml_dsa_65_verify(&admin_pubkey, &stored.sig_admin_outer, &body_bytes)?;

        // 6. Verify inner_payload_hash from stored outer matches the
        //    inner the vault submitted. This is the key bind: only an
        //    inner whose hash the admin signed can pass.
        let inner_bytes = cbor_to_vec(&req.invite_inner)
            .map_err(|e| CoreError::Crypto(CryptoError::AdminChain(format!("inner CBOR: {e}"))))?;
        let mut inner_hash = [0u8; 32];
        let digest = sha2::Sha256::digest(&inner_bytes);
        inner_hash.copy_from_slice(&digest);
        if inner_hash[..] != stored.inner_payload_hash[..] {
            return Err(CoreError::Auth(AuthError::InviteUsedOrExpired));
        }

        // 7. Verify vault's signature over (invite_nonce || vault_pubkey).
        let mut signed = Vec::new();
        signed.extend_from_slice(&nonce);
        signed.extend_from_slice(req.vault_pubkey.as_bytes());
        crate::crypto::pq::ml_dsa_65_verify(&req.vault_pubkey, &req.sig_vault, &signed)?;

        // 8. Allocate vault id + insert. Re-borrow mutably here.
        let vault_id = {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&random_bytes(16).expect("rng"));
            VaultId(buf)
        };
        {
            let cluster = state
                .clusters
                .get_mut(&cluster_id)
                .ok_or_else(|| CoreError::Auth(AuthError::Forbidden))?;
            cluster.vaults.push(VaultRecord {
                vault_id,
                vault_pubkey: req.vault_pubkey.clone(),
                last_seen_ms: None,
                status: VaultStatus::Online,
                sealed_meta: vec![], // Real hub seals vault_name + role + ts here.
                multiaddrs: vec![],
            });
        }
        state.invite_used.insert(nonce, ());

        Ok(AcceptResponse {
            cluster_id,
            vault_id,
            cluster_admin_pubkey: admin_pubkey,
            chain_head,
            invite_outer: stored,
        })
    }

    async fn get_admin_chain_head(
        &self,
        session_token: &SessionToken,
        cluster_id: &ClusterId,
    ) -> Result<AdminChainEntry, CoreError> {
        let state = self.state.lock().expect("poisoned");
        let _ = self.lookup_session(&state, session_token)?;
        let cluster = state
            .clusters
            .get(cluster_id)
            .ok_or_else(|| CoreError::Auth(AuthError::Forbidden))?;
        cluster
            .chain
            .last()
            .cloned()
            .ok_or_else(|| CoreError::Crypto(CryptoError::AdminChain("empty chain".into())))
    }

    async fn get_admin_chain(
        &self,
        session_token: &SessionToken,
        cluster_id: &ClusterId,
        from_seq: u64,
    ) -> Result<Vec<AdminChainEntry>, CoreError> {
        let state = self.state.lock().expect("poisoned");
        let _ = self.lookup_session(&state, session_token)?;
        let cluster = state
            .clusters
            .get(cluster_id)
            .ok_or_else(|| CoreError::Auth(AuthError::Forbidden))?;
        Ok(cluster
            .chain
            .iter()
            .filter(|e| e.seq >= from_seq)
            .cloned()
            .collect())
    }

    async fn get_vault_pubkey(
        &self,
        vault_id: &VaultId,
    ) -> Result<crate::crypto::pq::MlDsa65PublicKey, CoreError> {
        let state = self.state.lock().expect("poisoned");
        for cluster in state.clusters.values() {
            for v in &cluster.vaults {
                if v.vault_id == *vault_id {
                    return Ok(v.vault_pubkey.clone());
                }
            }
        }
        Err(CoreError::Auth(AuthError::Forbidden))
    }

    async fn touch_vault_last_seen(&self, vault_id: &VaultId, ts_ms: u64) -> Result<(), CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        for cluster in state.clusters.values_mut() {
            for v in cluster.vaults.iter_mut() {
                if v.vault_id == *vault_id {
                    v.last_seen_ms = Some(ts_ms);
                    return Ok(());
                }
            }
        }
        Err(CoreError::Auth(AuthError::Forbidden))
    }

    async fn get_chain_head_for_vault(
        &self,
        vault_id: &VaultId,
    ) -> Result<AdminChainEntry, CoreError> {
        let state = self.state.lock().expect("poisoned");
        for cluster in state.clusters.values() {
            if cluster.vaults.iter().any(|v| v.vault_id == *vault_id) {
                return cluster
                    .chain
                    .last()
                    .cloned()
                    .ok_or_else(|| CoreError::Crypto(CryptoError::AdminChain("empty".into())));
            }
        }
        Err(CoreError::Auth(AuthError::Forbidden))
    }

    async fn update_vault_multiaddrs(
        &self,
        vault_id: &VaultId,
        multiaddrs: Vec<String>,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        for cluster in state.clusters.values_mut() {
            if let Some(v) = cluster.vaults.iter_mut().find(|v| v.vault_id == *vault_id) {
                v.multiaddrs = multiaddrs;
                return Ok(());
            }
        }
        Err(CoreError::Auth(AuthError::Forbidden))
    }

    async fn get_user_identity_pubkey(
        &self,
        cluster_id: &ClusterId,
        user_id: &UserId,
    ) -> Result<crate::crypto::pq::MlDsa65PublicKey, CoreError> {
        let state = self.state.lock().expect("poisoned");
        for user in state.users_by_lookup.values() {
            if user.cluster_id == *cluster_id && user.user_id == *user_id {
                return Ok(user.identity_pubkey.clone());
            }
        }
        Err(CoreError::Auth(AuthError::Forbidden))
    }

    async fn append_admin_chain(
        &self,
        session_token: &SessionToken,
        cluster_id: &ClusterId,
        entries: Vec<AdminChainEntry>,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let _ = self.lookup_session(&state, session_token)?;
        let cluster = state
            .clusters
            .get_mut(cluster_id)
            .ok_or_else(|| CoreError::Auth(AuthError::Forbidden))?;
        let mut combined = cluster.chain.clone();
        combined.extend(entries);
        // Outer-only verify (hub-blind: no cluster_shared_key).
        crate::crypto::admin_chain::verify_chain_outer_only(
            &cluster.admin_pubkey,
            *cluster_id,
            &combined,
        )?;
        cluster.chain = combined;
        Ok(())
    }

    // ── Subdomains (managed-base namespaces) ───────────────────

    async fn claim_subdomain(
        &self,
        session_token: &SessionToken,
        claim: SubdomainClaim,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let session = self.lookup_session(&state, session_token)?;
        let user_id = session.user_id;
        let cluster_id = session.cluster_id;

        // 1. Reserved-names check.
        if is_reserved_subdomain(claim.subdomain.as_str()) {
            return Err(CoreError::Validation(
                crate::errors::ValidationError::SubdomainReserved(
                    claim.subdomain.as_str().to_string(),
                ),
            ));
        }
        // 2. Verify the user signed the claim under the
        // identity pubkey embedded in it.
        claim
            .verify()
            .map_err(|e| CoreError::Protocol(e))?;
        // 3. Already-taken under (base, sub).
        let key = (claim.base_domain.clone(), claim.subdomain.clone());
        if state.subdomains.contains_key(&key) {
            return Err(CoreError::Validation(
                crate::errors::ValidationError::Other(format!(
                    "subdomain.taken: {}.{}",
                    claim.subdomain, claim.base_domain
                )),
            ));
        }
        // 4. One claim per cluster per base.
        if state
            .subdomains
            .values()
            .any(|s| s.cluster_id == cluster_id && s.claim.base_domain == claim.base_domain)
        {
            return Err(CoreError::Validation(
                crate::errors::ValidationError::Other(format!(
                    "subdomain.cluster_already_claimed_in_base: {}",
                    claim.base_domain
                )),
            ));
        }
        // (No server-side `subdomain == username` check — see
        // docs/threat-model.md#relaxed_posture.client_side_username_check_only)
        let now = self.now();
        state.subdomains.insert(
            key,
            SubdomainSlot {
                user_id,
                cluster_id,
                claim,
                claimed_at_ms: now,
            },
        );
        Ok(())
    }

    async fn release_subdomain(
        &self,
        session_token: &SessionToken,
        base_domain: &str,
        subdomain: &Subdomain,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let session = self.lookup_session(&state, session_token)?;
        let user_id = session.user_id;
        let key = (base_domain.to_string(), subdomain.clone());
        let slot = state.subdomains.get(&key).ok_or_else(|| {
            CoreError::Validation(crate::errors::ValidationError::Other(format!(
                "subdomain.not_found: {subdomain}.{base_domain}"
            )))
        })?;
        if slot.user_id != user_id {
            return Err(CoreError::Auth(AuthError::Forbidden));
        }
        let now = self.now();
        state.subdomains.remove(&key);
        state.tombstoned_subdomains.insert(key, now);
        Ok(())
    }

    async fn lookup_subdomain(
        &self,
        base_domain: &str,
        subdomain: &Subdomain,
    ) -> Result<SubdomainDirectoryEntry, CoreError> {
        let state = self.state.lock().unwrap();
        let key = (base_domain.to_string(), subdomain.clone());
        let slot = state.subdomains.get(&key).ok_or_else(|| {
            CoreError::Validation(crate::errors::ValidationError::Other(format!(
                "subdomain.not_found: {subdomain}.{base_domain}"
            )))
        })?;
        Ok(SubdomainDirectoryEntry {
            subdomain: slot.claim.subdomain.clone(),
            base_domain: slot.claim.base_domain.clone(),
            user_identity_pubkey: slot.claim.user_identity_pubkey.clone(),
            alias_kem_directory_pointer: format!(
                "{}.{}",
                slot.claim.subdomain, slot.claim.base_domain
            ),
        })
    }

    async fn list_managed_base_domains(&self) -> Result<Vec<String>, CoreError> {
        // The in-memory backend is permissive: every base the
        // user picks is treated as managed. Hub config in
        // production will gate this.
        Ok(vec!["vito.gg".into()])
    }

    // ── User-owned domains (DNS-verified) ──────────────────────

    async fn add_domain(
        &self,
        session_token: &SessionToken,
        domain: &str,
    ) -> Result<DomainChallenge, CoreError> {
        let mut state = self.state.lock().unwrap();
        let session = self.lookup_session(&state, session_token)?;
        let user_id = session.user_id;
        let key = (user_id, domain.to_string());
        if state.domains.contains_key(&key) {
            return Err(CoreError::Validation(
                crate::errors::ValidationError::Other(format!("domain.already_added: {domain}")),
            ));
        }
        let mut challenge = [0u8; 32];
        let bytes =
            random_bytes(32).map_err(|e| CoreError::Crypto(CryptoError::Random(e.to_string())))?;
        challenge.copy_from_slice(&bytes);
        state.domains.insert(
            key,
            DomainSlot {
                status: DomainStatus::Pending,
                challenge,
                verified_at_ms: None,
            },
        );
        Ok(DomainChallenge {
            txt_record_value: b64url_encode(&challenge),
            required_mx_target: "mx.vitonomi.com".into(),
        })
    }

    async fn verify_domain(
        &self,
        session_token: &SessionToken,
        domain: &str,
    ) -> Result<DomainVerified, CoreError> {
        // The in-memory backend skips real DNS — production code
        // will inject a `DnsResolver` and resolve `_vitonomi.<d>`
        // TXT + MX. For now we mark verified unconditionally so
        // tests can drive the happy path.
        let mut state = self.state.lock().unwrap();
        let session = self.lookup_session(&state, session_token)?;
        let user_id = session.user_id;
        let key = (user_id, domain.to_string());
        let slot = state.domains.get_mut(&key).ok_or_else(|| {
            CoreError::Validation(crate::errors::ValidationError::Other(format!(
                "domain.not_found: {domain}"
            )))
        })?;
        let now = self.now();
        slot.status = DomainStatus::Active;
        slot.verified_at_ms = Some(now);
        Ok(DomainVerified {
            domain: domain.to_string(),
            verified_at_ms: now,
        })
    }

    async fn list_domains(
        &self,
        session_token: &SessionToken,
    ) -> Result<Vec<DomainRecord>, CoreError> {
        let state = self.state.lock().unwrap();
        let session = self.lookup_session(&state, session_token)?;
        let user_id = session.user_id;
        Ok(state
            .domains
            .iter()
            .filter(|((u, _), _)| *u == user_id)
            .map(|((_, d), s)| DomainRecord {
                domain: d.clone(),
                status: s.status,
                verified_at_ms: s.verified_at_ms,
            })
            .collect())
    }

    async fn remove_domain(
        &self,
        session_token: &SessionToken,
        domain: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let session = self.lookup_session(&state, session_token)?;
        let user_id = session.user_id;
        state.domains.remove(&(user_id, domain.to_string()));
        Ok(())
    }

    // ── Alias directory ────────────────────────────────────────

    async fn publish_alias_pubkey(
        &self,
        session_token: &SessionToken,
        entry: AliasDirectoryEntry,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let session = self.lookup_session(&state, session_token)?;
        // The session-bound user must own `entry.namespace` —
        // either they hold a subdomain claim under it, or they
        // verified it as a custom domain. Skip the deep check
        // here; production code wires it via the trait
        // helpers above.
        let _ = session;
        // Verify the user's signature over the entry. Both sides
        // use the canonical `AliasDirectoryEntry::signed_bytes`
        // helper so the recipe stays in lockstep.
        let msg = entry.signed_bytes().map_err(CoreError::Protocol)?;
        ml_dsa_65_verify(&entry.user_identity_pubkey, &entry.sig_user, &msg)
            .map_err(|_| {
                CoreError::Protocol(crate::errors::ProtocolError::Malformed(
                    "alias_directory: sig_user invalid".into(),
                ))
            })?;
        let key = (entry.alias_handle.clone(), entry.namespace.clone());
        state.alias_directory.insert(key, entry);
        Ok(())
    }

    async fn lookup_alias_pubkey(
        &self,
        alias_handle: &str,
        namespace: &str,
    ) -> Result<AliasDirectoryEntry, CoreError> {
        let state = self.state.lock().unwrap();
        state
            .alias_directory
            .get(&(alias_handle.to_string(), namespace.to_string()))
            .cloned()
            .ok_or_else(|| {
                CoreError::Validation(crate::errors::ValidationError::Other(format!(
                    "alias_directory.not_found: {alias_handle}@{namespace}"
                )))
            })
    }

    async fn revoke_alias_pubkey(
        &self,
        session_token: &SessionToken,
        alias_handle: &str,
        namespace: &str,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let _ = self.lookup_session(&state, session_token)?;
        state
            .alias_directory
            .remove(&(alias_handle.to_string(), namespace.to_string()));
        Ok(())
    }

    // ── Per-alias inbound queue (shape A) ──────────────────────

    async fn mx_relay_push_inbound(
        &self,
        push: SignedMxRelayPush,
    ) -> Result<MxRelayPushAck, CoreError> {
        let mut state = self.state.lock().unwrap();
        // 1. Verify the mx relay's signature.
        let registration = state.mx_relay_pubkeys.get(&push.mx_relay_id).ok_or_else(|| {
            CoreError::Auth(AuthError::Forbidden)
        })?;
        let signed = push.signed_bytes().map_err(CoreError::Protocol)?;
        ml_dsa_65_verify(&registration.pubkey, &push.sig_mx_relay, &signed).map_err(|_| {
            CoreError::Protocol(crate::errors::ProtocolError::Malformed(
                "mx_relay_push: sig_mx_relay invalid".into(),
            ))
        })?;
        // 2. Resolve alias from the directory.
        let (alias_handle, namespace) = &push.alias_directory_lookup;
        let entry = state
            .alias_directory
            .get(&(alias_handle.clone(), namespace.clone()))
            .cloned();
        let Some(entry) = entry else {
            // Silent drop — no log of the alias address.
            return Ok(MxRelayPushAck { received: false });
        };
        let alias_id = entry.alias_id;
        // 3. Append to the per-alias FIFO under a fresh seq.
        let seq = {
            let counter = state.inbox_seq_counters.entry(alias_id).or_insert(0);
            *counter += 1;
            *counter
        };
        let envelope = InboundEnvelope {
            seq,
            alias_id,
            envelope: push.envelope,
            server_received_at_ms: push.server_received_at_ms,
        };
        state
            .inbound_queues
            .entry(alias_id)
            .or_insert_with(Vec::new)
            .push(envelope);
        Ok(MxRelayPushAck { received: true })
    }

    async fn fetch_alias_inbox(
        &self,
        session_token: &SessionToken,
        alias_id: &RecordId,
        since_seq: u64,
    ) -> Result<Vec<InboundEnvelope>, CoreError> {
        let state = self.state.lock().unwrap();
        let _ = self.lookup_session(&state, session_token)?;
        let queue = state.inbound_queues.get(alias_id);
        Ok(queue
            .map(|q| q.iter().filter(|e| e.seq > since_seq).cloned().collect())
            .unwrap_or_default())
    }

    async fn ack_alias_inbox(
        &self,
        session_token: &SessionToken,
        alias_id: &RecordId,
        up_to_seq: u64,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let _ = self.lookup_session(&state, session_token)?;
        state.inbox_acks.insert(*alias_id, up_to_seq);
        // Best-effort GC: drop ack'd envelopes from the queue.
        if let Some(q) = state.inbound_queues.get_mut(alias_id) {
            q.retain(|e| e.seq > up_to_seq);
        }
        Ok(())
    }

    // ── Mx-relay identity registration ─────────────────────────

    async fn register_mx_relay_identity(
        &self,
        session_token: &SessionToken,
        req: RegisterMxRelayRequest,
    ) -> Result<(), CoreError> {
        let mut state = self.state.lock().unwrap();
        let _ = self.lookup_session(&state, session_token)?;
        // Production gates this on an admin role; in-memory
        // backend is permissive (any session can register).
        // `MxRelayId` derives deterministically from the pubkey —
        // both sides compute the same value, so the mx relay never
        // has to learn it from a hub response.
        let mx_relay_id = MxRelayId::from_pubkey(&req.mx_relay_pubkey);
        state.mx_relay_pubkeys.insert(
            mx_relay_id,
            MxRelayRegistration {
                pubkey: req.mx_relay_pubkey,
                allowed_namespaces: req.allowed_namespaces,
            },
        );
        Ok(())
    }

    async fn lookup_mx_relay_pubkey(
        &self,
        mx_relay_id: &MxRelayId,
    ) -> Result<MlDsa65PublicKey, CoreError> {
        let state = self.state.lock().unwrap();
        state
            .mx_relay_pubkeys
            .get(mx_relay_id)
            .map(|r| r.pubkey.clone())
            .ok_or_else(|| {
                CoreError::Validation(crate::errors::ValidationError::Other(
                    "mx_relay.not_found".into(),
                ))
            })
    }
}

struct UserSnapshot {
    user_id: UserId,
    encrypted_key_blob: Vec<u8>,
}
