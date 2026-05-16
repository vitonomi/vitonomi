//! Shared fixtures for the hub-control-plane test files. Put in
//! `tests/common/mod.rs` (NOT `tests/common.rs`) so Rust treats it
//! as a submodule rather than a standalone test binary.

use vitonomi_core::crypto::admin_chain::{sign_entry, AdminAction, GENESIS_PREV_HASH};
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keys::{GenesisMaterial, MasterPublicKeys};
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::crypto::pq::{
    ml_dsa_65_sign, MlDsa65Keypair, MlDsa65Signature, MlKem768PublicKey,
};
use vitonomi_core::protocol::hub_control_plane::{ClusterRegisterRequest, HubControlPlane};
use vitonomi_core::protocol::testing::in_memory_hub::InMemoryHubControlPlane;
use vitonomi_core::protocol::wire::aliases::AliasDirectoryEntry;
use vitonomi_core::protocol::wire::login::UserLookupId;
use vitonomi_core::record::RecordId;
use vitonomi_core::types::subdomain::{Subdomain, SubdomainClaim};
use vitonomi_core::types::{ClusterId, FormatVersion, SessionToken, Username};

pub fn fast_lookup_params() -> LookupIdParams {
    LookupIdParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

/// Boot an in-memory hub + register one cluster + return the session
/// token plus the user's identity keypair (for signing claims /
/// alias-directory entries).
pub async fn bootstrap_user(
    username_str: &str,
) -> (InMemoryHubControlPlane, SessionToken, MlDsa65Keypair, ClusterId) {
    let hub = InMemoryHubControlPlane::new();
    let g = GenesisMaterial::generate().expect("genesis");
    let pubkeys = MasterPublicKeys::from(&g.master_keys);
    let cluster_id = cluster_id_of(&pubkeys.cluster_admin, FormatVersion::V1);
    let username = Username::parse(username_str).unwrap();
    let lookup_bytes =
        compute_lookup_id(&username, &g.cluster_pepper, &cluster_id, fast_lookup_params())
            .expect("lookup");
    let lookup_id = UserLookupId(lookup_bytes.to_vec());
    let genesis = sign_entry(
        &g.master_keys.cluster_admin.secret,
        &g.cluster_shared_key,
        cluster_id,
        GENESIS_PREV_HASH,
        0,
        AdminAction::ClusterInit,
        b"genesis".to_vec(),
    )
    .unwrap();
    let resp = hub
        .register_cluster(ClusterRegisterRequest {
            lookup_id,
            master_pubkeys: pubkeys,
            encrypted_key_blob: vec![0xab; 64],
            genesis_entry: genesis,
        })
        .await
        .expect("register cluster");
    let identity = MlDsa65Keypair {
        public: g.master_keys.identity.public.clone(),
        secret: vitonomi_core::crypto::pq::MlDsa65SecretKey(g.master_keys.identity.secret.0.clone()),
    };
    (hub, resp.session_token, identity, cluster_id)
}

pub fn make_claim(sub: &str, base: &str, kp: &MlDsa65Keypair) -> SubdomainClaim {
    let s = Subdomain::parse(sub).unwrap();
    let mut claim = SubdomainClaim {
        format_version: FormatVersion::V1,
        subdomain: s,
        base_domain: base.into(),
        user_identity_pubkey: kp.public.clone(),
        claimed_at_ms: 1_700_000_000_000,
        sig_user: MlDsa65Signature(vec![]),
    };
    let msg = claim.to_signed_bytes().unwrap();
    claim.sig_user = ml_dsa_65_sign(&kp.secret, &msg).unwrap();
    claim
}

pub fn signed_alias_entry(
    alias_handle: &str,
    namespace: &str,
    alias_id: RecordId,
    alias_kem_pubkey: &MlKem768PublicKey,
    user_identity_kp: &MlDsa65Keypair,
) -> AliasDirectoryEntry {
    let mut entry = AliasDirectoryEntry {
        alias_handle: alias_handle.into(),
        namespace: namespace.into(),
        alias_id,
        alias_kem_pubkey: alias_kem_pubkey.clone(),
        user_identity_pubkey: user_identity_kp.public.clone(),
        sig_user: MlDsa65Signature(vec![]),
    };
    let msg = entry.signed_bytes().unwrap();
    entry.sig_user = ml_dsa_65_sign(&user_identity_kp.secret, &msg).unwrap();
    entry
}
