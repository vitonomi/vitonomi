//! End-to-end exercise of the in-memory hub through the same trait
//! surface the real hub will implement. Catches regressions across
//! the whole register → invite → accept → restore flow.

use vitonomi_core::crypto::admin_chain::{entry_hash, sign_entry, AdminAction, GENESIS_PREV_HASH};
use vitonomi_core::crypto::argon2::Argon2Params;
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keys::{MasterKeys, MasterPublicKeys};
use vitonomi_core::crypto::pq::ml_dsa_65_sign;
use vitonomi_core::encoding::cbor_to_vec;
use vitonomi_core::protocol::hub_control_plane::{
    ClusterRegisterRequest, ClusterRestoreRequest, HubControlPlane,
};
use vitonomi_core::protocol::testing::in_memory_hub::InMemoryHubControlPlane;
use vitonomi_core::protocol::wire::accept::{
    AcceptRequest, CreateInviteRequest, InviteToken, InviteTokenBody, VaultRole,
};
use vitonomi_core::protocol::wire::admin_chain::ChainExport;
use vitonomi_core::types::{FormatVersion, Username};

#[tokio::test]
async fn register_login_invite_accept_round_trip() {
    let hub = InMemoryHubControlPlane::new();

    // Generate a master-key bundle for the cluster admin.
    let mk = MasterKeys::generate().expect("master keys");
    let master_pubkeys = MasterPublicKeys::from(&mk);
    let cluster_id = cluster_id_of(&master_pubkeys.cluster_admin, FormatVersion::V1);

    // Build the genesis admin-chain entry.
    let genesis = sign_entry(
        &mk.cluster_admin.secret,
        cluster_id,
        GENESIS_PREV_HASH,
        0,
        AdminAction::ClusterInit,
        b"genesis".to_vec(),
    )
    .expect("genesis");

    // Register the cluster.
    let resp = hub
        .register_cluster(ClusterRegisterRequest {
            username: Username::parse("birkeal").unwrap(),
            master_pubkeys: master_pubkeys.clone(),
            auth_salt: vec![1u8; 16],
            enc_salt: vec![2u8; 16],
            argon2_params: Argon2Params::default_for_env(),
            encrypted_key_blob: vec![0xab; 64],
            genesis_entry: genesis.clone(),
        })
        .await
        .expect("register");
    assert_eq!(resp.cluster_id, cluster_id);

    // Admin signs an invite for a vault.
    let invite_nonce = vec![0xcc; 32];
    let invite_body = InviteTokenBody {
        format_version: FormatVersion::V1,
        cluster_id,
        vault_role: VaultRole::Storage,
        hub_url: "https://localhost:0".into(),
        hub_cert_fingerprint: "sha256:test-fp".into(),
        invite_nonce: invite_nonce.clone(),
        expires_at_ms: u64::MAX,
    };
    let body_bytes = cbor_to_vec(&invite_body).unwrap();
    let admin_sig = ml_dsa_65_sign(&mk.cluster_admin.secret, &body_bytes).expect("invite sign");
    let invite = InviteToken {
        body: invite_body,
        sig_cluster_admin: admin_sig,
    };

    let invite_resp = hub
        .create_vault_invite(
            &resp.session_token,
            CreateInviteRequest {
                invite: invite.clone(),
            },
        )
        .await
        .expect("create invite");
    assert_eq!(invite_resp.invite, invite);

    // A fresh vault keypair accepts the invite.
    let vault_kp = vitonomi_core::crypto::pq::ml_dsa_65_keypair().expect("vault kp");
    let mut signed_payload = invite_nonce.clone();
    signed_payload.extend_from_slice(vault_kp.public.as_bytes());
    let vault_sig = ml_dsa_65_sign(&vault_kp.secret, &signed_payload).expect("vault sig");

    let accept = hub
        .accept_vault_invite(AcceptRequest {
            invite,
            vault_pubkey: vault_kp.public.clone(),
            vault_name: "pi-1".into(),
            sig_vault: vault_sig,
        })
        .await
        .expect("accept");
    assert_eq!(accept.cluster_id, cluster_id);
    assert!(accept
        .cluster_admin_pubkey
        .ct_eq(&master_pubkeys.cluster_admin));

    // The hub should now list pi-1.
    let vaults = hub.list_vaults(&resp.session_token).await.expect("list");
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].name, "pi-1");
}

#[tokio::test]
async fn cluster_restore_to_fresh_hub() {
    let hub_a = InMemoryHubControlPlane::new();
    let hub_b = InMemoryHubControlPlane::new();

    let mk = MasterKeys::generate().expect("master keys");
    let master_pubkeys = MasterPublicKeys::from(&mk);
    let cluster_id = cluster_id_of(&master_pubkeys.cluster_admin, FormatVersion::V1);

    // Build a 2-entry chain: cluster-init + vault-enroll, both
    // admin-signed. Mirrors what the real hub would have after a
    // single accept.
    let e0 = sign_entry(
        &mk.cluster_admin.secret,
        cluster_id,
        GENESIS_PREV_HASH,
        0,
        AdminAction::ClusterInit,
        vec![],
    )
    .unwrap();
    let e0_hash = entry_hash(&e0).unwrap();
    let e1 = sign_entry(
        &mk.cluster_admin.secret,
        cluster_id,
        e0_hash,
        1,
        AdminAction::VaultEnroll,
        b"vault=pi-1".to_vec(),
    )
    .unwrap();

    // Register cluster on hub-A with just the genesis entry.
    let _ = hub_a
        .register_cluster(ClusterRegisterRequest {
            username: Username::parse("birkeal").unwrap(),
            master_pubkeys: master_pubkeys.clone(),
            auth_salt: vec![1u8; 16],
            enc_salt: vec![2u8; 16],
            argon2_params: Argon2Params::default_for_env(),
            encrypted_key_blob: vec![0xab; 64],
            genesis_entry: e0.clone(),
        })
        .await
        .expect("register A");

    // Restore the same cluster onto hub-B with the full chain.
    let restore_resp = hub_b
        .restore_cluster(ClusterRestoreRequest {
            username: Username::parse("birkeal").unwrap(),
            master_pubkeys,
            auth_salt: vec![1u8; 16],
            enc_salt: vec![2u8; 16],
            argon2_params: Argon2Params::default_for_env(),
            encrypted_key_blob: vec![0xab; 64],
            chain_export: ChainExport {
                cluster_id,
                entries: vec![e0, e1.clone()],
            },
        })
        .await
        .expect("restore B");
    assert_eq!(restore_resp.cluster_id, cluster_id);

    // Hub-B's chain head should match the imported tail.
    let head = hub_b
        .get_admin_chain_head(&restore_resp.session_token, &cluster_id)
        .await
        .expect("head");
    assert_eq!(head.seq, 1);
    assert_eq!(head, e1);
}
