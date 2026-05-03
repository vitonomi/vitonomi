//! In-memory `HubControlPlane` implementation for integration tests.
//!
//! Maintains a `Mutex<HubState>` matching the real hub's data model
//! at the trait granularity: clusters, users, vaults, sessions,
//! invite nonces, key blobs, admin chains. Exercises the *same*
//! crypto verifications the real hub does (genesis-entry
//! verification on register, signature on accept, chain verify on
//! restore).

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::crypto::admin_chain::{
    verify_chain, verify_entry, AdminAction, AdminChainEntry, GENESIS_PREV_HASH,
};
use crate::crypto::challenge::{verify_challenge, Challenge};
use crate::crypto::cluster::{cluster_id_of, verify_invite_payload};
use crate::crypto::keys::MasterPublicKeys;
use crate::crypto::pq::MlDsa65PublicKey;
use crate::crypto::random::random_bytes;
use crate::encoding::{b64url_encode, cbor_to_vec};
use crate::errors::{AuthError, CoreError, CryptoError, ProtocolError};
use crate::protocol::hub_control_plane::{
    ClusterRegisterRequest, ClusterRegisterResponse, ClusterRestoreRequest, HubControlPlane,
    VaultRecord, VaultStatus,
};
use crate::protocol::wire::accept::{
    AcceptRequest, AcceptResponse, CreateInviteRequest, CreateInviteResponse,
};
use crate::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
};
use crate::types::{ClusterId, FormatVersion, SessionToken, UserId, Username, VaultId};

#[derive(Default)]
struct HubState {
    clusters: HashMap<ClusterId, ClusterRecord>,
    users_by_username: HashMap<Username, UserRecord>,
    sessions: HashMap<String, Session>,
    challenges: HashMap<String, PendingChallenge>,
    invite_used: HashMap<Vec<u8>, ()>,
}

struct ClusterRecord {
    admin_pubkey: MlDsa65PublicKey,
    chain: Vec<AdminChainEntry>,
    vaults: Vec<VaultRecord>,
}

struct UserRecord {
    user_id: UserId,
    cluster_id: ClusterId,
    master_pubkeys: MasterPublicKeys,
    auth_salt: Vec<u8>,
    enc_salt: Vec<u8>,
    argon2_params: crate::crypto::argon2::Argon2Params,
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

struct UserSnapshot {
    user_id: UserId,
    auth_salt: Vec<u8>,
    enc_salt: Vec<u8>,
    argon2_params: crate::crypto::argon2::Argon2Params,
    encrypted_key_blob: Vec<u8>,
}

/// In-memory hub for integration tests. Cheap to construct; keep
/// one per test for isolation.
pub struct InMemoryHubControlPlane {
    state: Mutex<HubState>,
    clock_ms: fn() -> u64,
}

impl InMemoryHubControlPlane {
    /// Build a hub using the system clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HubState::default()),
            clock_ms: default_clock_ms,
        }
    }

    /// Build a hub with a custom clock function (useful for testing
    /// expiry windows deterministically).
    #[must_use]
    pub fn with_clock(clock_ms: fn() -> u64) -> Self {
        Self {
            state: Mutex::new(HubState::default()),
            clock_ms,
        }
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
        if state.users_by_username.contains_key(&req.username) {
            return Err(CoreError::Auth(AuthError::Forbidden));
        }
        // Verify genesis entry signature against the admin pubkey.
        verify_entry(&req.master_pubkeys.cluster_admin, &req.genesis_entry)?;
        if req.genesis_entry.cluster_id != cluster_id
            || req.genesis_entry.seq != 0
            || req.genesis_entry.action != AdminAction::ClusterInit
            || req.genesis_entry.prev_hash != GENESIS_PREV_HASH
        {
            return Err(CoreError::Crypto(CryptoError::AdminChain(
                "genesis entry mismatched cluster_id / seq / action / prev_hash".into(),
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
        state.users_by_username.insert(
            req.username.clone(),
            UserRecord {
                user_id,
                cluster_id,
                master_pubkeys: req.master_pubkeys,
                auth_salt: req.auth_salt,
                enc_salt: req.enc_salt,
                argon2_params: req.argon2_params,
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
        verify_chain(
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
        state.users_by_username.insert(
            req.username.clone(),
            UserRecord {
                user_id,
                cluster_id,
                master_pubkeys: req.master_pubkeys,
                auth_salt: req.auth_salt,
                enc_salt: req.enc_salt,
                argon2_params: req.argon2_params,
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

    async fn login_start(&self, req: LoginStartRequest) -> Result<LoginStartResponse, CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        // Snapshot what we need from the user record while only
        // holding an immutable borrow.
        let snapshot = {
            let user = state
                .users_by_username
                .get(&req.username)
                .ok_or_else(|| CoreError::Auth(AuthError::InvalidCredentials))?;
            UserSnapshot {
                user_id: user.user_id,
                auth_salt: user.auth_salt.clone(),
                enc_salt: user.enc_salt.clone(),
                argon2_params: user.argon2_params,
                encrypted_key_blob: user.encrypted_key_blob.clone(),
            }
        };

        let challenge = Challenge::generate(self.now())?;
        let challenge_id = b64url_encode(&random_bytes(16).expect("rng"));
        let expires_at_ms = self.now() + 5 * 60 * 1000;

        let resp = LoginStartResponse {
            auth_salt: snapshot.auth_salt,
            enc_salt: snapshot.enc_salt,
            argon2_params: snapshot.argon2_params,
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
        // Find the user's identity pubkey via cluster_id reverse lookup.
        let user = state
            .users_by_username
            .values()
            .find(|u| u.user_id == pending.user_id)
            .ok_or_else(|| CoreError::Auth(AuthError::SessionUnknown))?;
        verify_challenge(
            &user.master_pubkeys.identity,
            &pending.challenge,
            &req.signature,
        )?;
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
            .users_by_username
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
            .users_by_username
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
        Ok(cluster.vaults.clone())
    }

    async fn create_vault_invite(
        &self,
        session_token: &SessionToken,
        req: CreateInviteRequest,
    ) -> Result<CreateInviteResponse, CoreError> {
        let state = self.state.lock().expect("poisoned");
        let cluster_id = self.lookup_session(&state, session_token)?.cluster_id;
        let cluster = state
            .clusters
            .get(&cluster_id)
            .ok_or_else(|| CoreError::Auth(AuthError::SessionUnknown))?;
        // Verify the invite is signed by *this* cluster's admin.
        let body_bytes = cbor_to_vec(&req.invite.body)
            .map_err(|e| CoreError::Protocol(ProtocolError::Cbor(e.to_string())))?;
        verify_invite_payload(
            &cluster.admin_pubkey,
            &body_bytes,
            &req.invite.sig_cluster_admin,
        )?;
        if req.invite.body.cluster_id != cluster_id {
            return Err(CoreError::Crypto(CryptoError::AdminChain(
                "invite cluster_id mismatch".into(),
            )));
        }
        // Note: we don't track "issued but unused" invites in the
        // in-memory hub. The real hub does, to support TTL expiry +
        // listing. `invite_used` is populated on accept (replay
        // defense).
        Ok(CreateInviteResponse { invite: req.invite })
    }

    async fn accept_vault_invite(&self, req: AcceptRequest) -> Result<AcceptResponse, CoreError> {
        let mut state = self.state.lock().expect("poisoned");
        let cluster_id = req.invite.body.cluster_id;
        let nonce = req.invite.body.invite_nonce.clone();

        // 1. Expiry + replay check (don't need any cluster borrow).
        if req.invite.body.expires_at_ms < self.now() {
            return Err(CoreError::Auth(AuthError::InviteUsedOrExpired));
        }
        if state.invite_used.contains_key(&nonce) {
            return Err(CoreError::Auth(AuthError::InviteUsedOrExpired));
        }

        // 2. Snapshot admin pubkey + chain head while holding only an
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

        // 3. Re-verify admin signature on the invite.
        let body_bytes = cbor_to_vec(&req.invite.body)
            .map_err(|e| CoreError::Protocol(ProtocolError::Cbor(e.to_string())))?;
        verify_invite_payload(&admin_pubkey, &body_bytes, &req.invite.sig_cluster_admin)?;

        // 4. Verify vault signature over (invite_nonce || vault_pubkey_bytes).
        let mut signed = Vec::new();
        signed.extend_from_slice(&nonce);
        signed.extend_from_slice(req.vault_pubkey.as_bytes());
        crate::crypto::pq::ml_dsa_65_verify(&req.vault_pubkey, &req.sig_vault, &signed)?;

        // 5. Allocate vault id + insert. We re-borrow mutably here.
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
                name: req.vault_name,
                last_seen_ms: None,
                status: VaultStatus::Online,
            });
        }
        state.invite_used.insert(nonce, ());

        Ok(AcceptResponse {
            cluster_id,
            vault_id,
            cluster_admin_pubkey: admin_pubkey,
            chain_head,
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
        verify_chain(&cluster.admin_pubkey, *cluster_id, &combined)?;
        cluster.chain = combined;
        Ok(())
    }
}
