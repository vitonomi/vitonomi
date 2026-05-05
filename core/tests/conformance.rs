//! End-to-end exercise of the in-memory hub through the same trait
//! surface the real hub will implement. Hub-blind: uses `lookup_id`,
//! sealed admin chain entries, and the K2 invite outer/inner split.

use sha2::Digest as _;

use vitonomi_core::crypto::admin_chain::{sign_entry, AdminAction, GENESIS_PREV_HASH};
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::cluster_keys::ClusterSharedKey;
use vitonomi_core::crypto::keys::{GenesisMaterial, MasterPublicKeys};
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::crypto::pq::ml_dsa_65_sign;
use vitonomi_core::encoding::cbor_to_vec;
use vitonomi_core::protocol::hub_control_plane::{
    ClusterRegisterRequest, ClusterRestoreRequest, HubControlPlane,
};
use vitonomi_core::protocol::testing::in_memory_hub::InMemoryHubControlPlane;
use vitonomi_core::protocol::wire::accept::{
    AcceptRequest, CreateInviteRequest, InviteInnerPayload, InviteOuterSummary, VaultRole,
};
use vitonomi_core::protocol::wire::admin_chain::ChainExport;
use vitonomi_core::protocol::wire::login::UserLookupId;
use vitonomi_core::types::{FormatVersion, Username};

fn fast_lookup_params() -> LookupIdParams {
    LookupIdParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

#[tokio::test]
async fn register_invite_accept_round_trip() {
    let hub = InMemoryHubControlPlane::new();

    let g = GenesisMaterial::generate().expect("genesis");
    let pubkeys = MasterPublicKeys::from(&g.master_keys);
    let cluster_id = cluster_id_of(&pubkeys.cluster_admin, FormatVersion::V1);

    let username = Username::parse("birkeal").unwrap();
    let lookup_bytes = compute_lookup_id(
        &username,
        &g.cluster_pepper,
        &cluster_id,
        fast_lookup_params(),
    )
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
            lookup_id: lookup_id.clone(),
            master_pubkeys: pubkeys.clone(),
            encrypted_key_blob: vec![0xab; 64],
            genesis_entry: genesis.clone(),
        })
        .await
        .expect("register");
    assert_eq!(resp.cluster_id, cluster_id);

    // Admin builds an invite (outer + inner). Inner contains the
    // sealed cluster_shared_key (here we elide the sealing for the
    // test — the in-memory hub never opens the inner; only the
    // inner_payload_hash matters).
    let invite_nonce = vec![0xcc; 32];
    let inner = InviteInnerPayload {
        format_version: FormatVersion::V1,
        vault_role: VaultRole::Storage,
        hub_url: "https://localhost:0".into(),
        hub_cert_fingerprint: "sha256:test-fingerprint-string-of-43-base64url-chars-x".into(),
        sealed_cluster_key: vec![0u8; 72],
    };
    let inner_bytes = cbor_to_vec(&inner).unwrap();
    let inner_hash = {
        let mut h = sha2::Sha256::new();
        h.update(&inner_bytes);
        h.finalize().to_vec()
    };

    let outer_unsigned_signed_bytes = {
        let mut buf = Vec::new();
        buf.push(FormatVersion::V1.as_u8());
        buf.extend_from_slice(cluster_id.as_bytes());
        buf.extend_from_slice(&invite_nonce);
        buf.extend_from_slice(&u64::MAX.to_be_bytes());
        buf.extend_from_slice(&inner_hash);
        buf
    };
    let sig_admin_outer = ml_dsa_65_sign(
        &g.master_keys.cluster_admin.secret,
        &outer_unsigned_signed_bytes,
    )
    .unwrap();

    let outer = InviteOuterSummary {
        format_version: FormatVersion::V1,
        cluster_id,
        invite_nonce: invite_nonce.clone(),
        expires_at_ms: u64::MAX,
        inner_payload_hash: inner_hash,
        sig_admin_outer,
    };

    let invite_resp = hub
        .create_vault_invite(
            &resp.session_token,
            CreateInviteRequest {
                invite: outer.clone(),
            },
        )
        .await
        .expect("create invite");
    assert_eq!(invite_resp.invite, outer);

    // Vault accepts.
    let vault_kp = vitonomi_core::crypto::pq::ml_dsa_65_keypair().expect("vault kp");
    let mut signed_payload = invite_nonce.clone();
    signed_payload.extend_from_slice(vault_kp.public.as_bytes());
    let sig_vault = ml_dsa_65_sign(&vault_kp.secret, &signed_payload).expect("vault sig");

    let accept = hub
        .accept_vault_invite(AcceptRequest {
            invite_outer: outer,
            invite_inner: inner,
            vault_pubkey: vault_kp.public.clone(),
            sig_vault,
        })
        .await
        .expect("accept");
    assert_eq!(accept.cluster_id, cluster_id);
    assert!(accept.cluster_admin_pubkey.ct_eq(&pubkeys.cluster_admin));

    let vaults = hub.list_vaults(&resp.session_token).await.expect("list");
    assert_eq!(vaults.len(), 1);
    assert!(vaults[0].vault_pubkey.ct_eq(&vault_kp.public));
}

#[tokio::test]
async fn cluster_restore_to_fresh_hub() {
    let hub_a = InMemoryHubControlPlane::new();
    let hub_b = InMemoryHubControlPlane::new();

    let g = GenesisMaterial::generate().expect("genesis");
    let pubkeys = MasterPublicKeys::from(&g.master_keys);
    let cluster_id = cluster_id_of(&pubkeys.cluster_admin, FormatVersion::V1);
    let csk = ClusterSharedKey(g.cluster_shared_key.0.clone());

    let username = Username::parse("birkeal").unwrap();
    let lookup_bytes = compute_lookup_id(
        &username,
        &g.cluster_pepper,
        &cluster_id,
        fast_lookup_params(),
    )
    .expect("lookup");
    let lookup_id = UserLookupId(lookup_bytes.to_vec());

    let e0 = sign_entry(
        &g.master_keys.cluster_admin.secret,
        &csk,
        cluster_id,
        GENESIS_PREV_HASH,
        0,
        AdminAction::ClusterInit,
        vec![],
    )
    .unwrap();
    let e0h = vitonomi_core::crypto::admin_chain::entry_hash(&e0).unwrap();
    let e1 = sign_entry(
        &g.master_keys.cluster_admin.secret,
        &csk,
        cluster_id,
        e0h,
        1,
        AdminAction::VaultEnroll,
        b"vault=pi-1".to_vec(),
    )
    .unwrap();

    let _ = hub_a
        .register_cluster(ClusterRegisterRequest {
            lookup_id: lookup_id.clone(),
            master_pubkeys: pubkeys.clone(),
            encrypted_key_blob: vec![0xab; 64],
            genesis_entry: e0.clone(),
        })
        .await
        .expect("register A");

    let restore_resp = hub_b
        .restore_cluster(ClusterRestoreRequest {
            lookup_id,
            master_pubkeys: pubkeys,
            encrypted_key_blob: vec![0xab; 64],
            chain_export: ChainExport {
                cluster_id,
                entries: vec![e0, e1.clone()],
            },
        })
        .await
        .expect("restore B");
    assert_eq!(restore_resp.cluster_id, cluster_id);

    let head = hub_b
        .get_admin_chain_head(&restore_resp.session_token, &cluster_id)
        .await
        .expect("head");
    assert_eq!(head.seq, 1);
    assert_eq!(head, e1);
}
