//! Vault → hub auto-bootstrap conformance tests against the in-memory
//! hub. Covers the happy path plus the high-value negative scenarios:
//! cluster_id / admin pubkey mismatch, tampered chain, swapped vault
//! signature, policy violation, idempotent re-bootstrap.

use vitonomi_core::crypto::admin_chain::{sign_entry, AdminAction, GENESIS_PREV_HASH};
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keys::GenesisMaterial;
use vitonomi_core::crypto::pq::{ml_dsa_65_keypair, ml_dsa_65_sign, MlDsa65Signature};
use vitonomi_core::protocol::hub_control_plane::HubControlPlane;
use vitonomi_core::protocol::testing::in_memory_hub::InMemoryHubControlPlane;
use vitonomi_core::protocol::wire::accept::{invite_outer_signed_bytes, InviteOuterSummary};
use vitonomi_core::protocol::wire::bootstrap::{BootstrapPolicy, BootstrapRequest};
use vitonomi_core::types::{ClusterId, FormatVersion};

/// Build a complete cluster + chain genesis + admin-signed invite +
/// vault keypair + vault signature — i.e. the durable on-disk state
/// a vault holds after a successful first `accept`.
struct VaultMaterial {
    cluster_admin_pubkey: vitonomi_core::crypto::pq::MlDsa65PublicKey,
    cluster_id: ClusterId,
    chain: Vec<vitonomi_core::crypto::admin_chain::AdminChainEntry>,
    invite_outer: InviteOuterSummary,
    vault_pubkey: vitonomi_core::crypto::pq::MlDsa65PublicKey,
    sig_vault: MlDsa65Signature,
}

fn build_vault_material() -> VaultMaterial {
    let g = GenesisMaterial::generate().expect("genesis");
    let cluster_id = cluster_id_of(&g.master_keys.cluster_admin.public, FormatVersion::V1);

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

    // Admin builds an invite and signs the outer.
    let invite_nonce = vec![0x42u8; 32];
    let inner_payload_hash = vec![0xaa; 32]; // arbitrary — bootstrap doesn't see inner
    let mut outer = InviteOuterSummary {
        format_version: FormatVersion::V1,
        cluster_id,
        invite_nonce: invite_nonce.clone(),
        expires_at_ms: u64::MAX,
        inner_payload_hash,
        sig_admin_outer: MlDsa65Signature(vec![]),
    };
    let signed = invite_outer_signed_bytes(&outer);
    outer.sig_admin_outer =
        ml_dsa_65_sign(&g.master_keys.cluster_admin.secret, &signed).expect("admin sign");

    // Vault generates its keypair and signs (invite_nonce || vault_pubkey_bytes).
    let vault_kp = ml_dsa_65_keypair().expect("vault keypair");
    let mut sig_input = invite_nonce.clone();
    sig_input.extend_from_slice(vault_kp.public.as_bytes());
    let sig_vault = ml_dsa_65_sign(&vault_kp.secret, &sig_input).expect("vault sign");

    VaultMaterial {
        cluster_admin_pubkey: g.master_keys.cluster_admin.public.clone(),
        cluster_id,
        chain: vec![genesis],
        invite_outer: outer,
        vault_pubkey: vault_kp.public,
        sig_vault,
    }
}

fn build_bootstrap_request(m: &VaultMaterial) -> BootstrapRequest {
    BootstrapRequest {
        cluster_admin_pubkey: m.cluster_admin_pubkey.clone(),
        chain_export: m.chain.clone(),
        vault_pubkey: m.vault_pubkey.clone(),
        invite_outer: m.invite_outer.clone(),
        sig_vault: m.sig_vault.clone(),
    }
}

#[tokio::test]
async fn happy_path_bootstrap_creates_cluster_and_vault() {
    let hub = InMemoryHubControlPlane::new();
    let m = build_vault_material();

    let resp = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .expect("bootstrap");
    assert_eq!(resp.cluster_id, m.cluster_id);
    assert!(resp.created_cluster);
    assert!(resp.created_vault);
    assert_ne!(resp.vault_id.0, [0u8; 16], "vault_id must be assigned");
}

#[tokio::test]
async fn second_bootstrap_is_idempotent_no_op() {
    let hub = InMemoryHubControlPlane::new();
    let m = build_vault_material();

    let first = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .unwrap();
    let second = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .unwrap();
    assert_eq!(first.vault_id, second.vault_id, "stable vault_id");
    assert!(!second.created_cluster);
    assert!(!second.created_vault);
}

#[tokio::test]
async fn tampered_chain_rejected() {
    let hub = InMemoryHubControlPlane::new();
    let mut m = build_vault_material();
    // Flip a byte in the genesis entry's outer signature.
    m.chain[0].sig_admin_outer.0[0] ^= 0x01;
    let err = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("signature") || msg.contains("Signature"),
        "expected signature error, got: {msg}"
    );
}

#[tokio::test]
async fn empty_chain_rejected() {
    let hub = InMemoryHubControlPlane::new();
    let mut m = build_vault_material();
    m.chain.clear();
    let err = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("empty"),
        "expected empty-chain error: {err}"
    );
}

#[tokio::test]
async fn tampered_invite_signature_rejected() {
    let hub = InMemoryHubControlPlane::new();
    let mut m = build_vault_material();
    m.invite_outer.sig_admin_outer.0[0] ^= 0x01;
    let err = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .unwrap_err();
    let msg = format!("{err}").to_lowercase();
    assert!(msg.contains("signature"), "expected signature error: {err}");
}

#[tokio::test]
async fn swapped_vault_signature_rejected() {
    let hub = InMemoryHubControlPlane::new();
    let mut m = build_vault_material();
    // Replace sig_vault with a signature from a different keypair —
    // even though it's a valid signature, it won't verify against
    // m.vault_pubkey.
    let other = ml_dsa_65_keypair().unwrap();
    let mut sig_input = m.invite_outer.invite_nonce.clone();
    sig_input.extend_from_slice(m.vault_pubkey.as_bytes());
    m.sig_vault = ml_dsa_65_sign(&other.secret, &sig_input).unwrap();
    let err = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("signature"));
}

#[tokio::test]
async fn invite_for_other_cluster_rejected() {
    let hub = InMemoryHubControlPlane::new();
    let mut m = build_vault_material();
    // Forge a different cluster_id in the invite — but keep its
    // signature pointing at the right admin key. The bytes won't
    // re-verify, but the cross-check is "invite.cluster_id ==
    // bootstrap.cluster_id" which we want to exercise too.
    m.invite_outer.cluster_id = ClusterId([0u8; 32]);
    let err = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .unwrap_err();
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("signature") || msg.contains("cluster_id"),
        "expected signature or cluster_id error: {err}"
    );
}

#[tokio::test]
async fn single_user_policy_blocks_second_cluster() {
    let hub = InMemoryHubControlPlane::new(); // default = SingleUser
    let m1 = build_vault_material();
    let m2 = build_vault_material(); // different admin keypair → different cluster_id

    hub.bootstrap_cluster(build_bootstrap_request(&m1))
        .await
        .unwrap();
    let err = hub
        .bootstrap_cluster(build_bootstrap_request(&m2))
        .await
        .unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("forbidden")
            || format!("{err}").to_lowercase().contains("auth"),
        "expected policy denial: {err}"
    );
}

#[tokio::test]
async fn allowlist_policy_admits_listed_only() {
    let m_allowed = build_vault_material();
    let m_blocked = build_vault_material();

    let hub = InMemoryHubControlPlane::new().with_bootstrap_policy(BootstrapPolicy::Allowlist {
        cluster_ids: vec![m_allowed.cluster_id],
    });

    hub.bootstrap_cluster(build_bootstrap_request(&m_allowed))
        .await
        .expect("allowed bootstrap");
    let err = hub
        .bootstrap_cluster(build_bootstrap_request(&m_blocked))
        .await
        .unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("forbidden"));
}

#[tokio::test]
async fn open_policy_admits_any_valid_cluster() {
    let hub = InMemoryHubControlPlane::new().with_bootstrap_policy(BootstrapPolicy::Open);
    for _ in 0..3 {
        let m = build_vault_material();
        hub.bootstrap_cluster(build_bootstrap_request(&m))
            .await
            .expect("open policy admits");
    }
}

#[tokio::test]
async fn cluster_id_pubkey_mismatch_rejected() {
    let hub = InMemoryHubControlPlane::new();
    let mut m = build_vault_material();
    // Replace the admin pubkey with an unrelated one. The chain
    // signatures won't verify under this pubkey AND
    // cluster_id_of(other_admin) != m.cluster_id.
    let other = ml_dsa_65_keypair().unwrap();
    m.cluster_admin_pubkey = other.public;
    let err = hub
        .bootstrap_cluster(build_bootstrap_request(&m))
        .await
        .unwrap_err();
    let msg = format!("{err}").to_lowercase();
    assert!(
        msg.contains("signature") || msg.contains("cluster_id"),
        "expected mismatch error: {err}"
    );
}
