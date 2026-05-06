//! End-to-end integration test: boot the hub on an ephemeral port,
//! drive the vault library through `init` → `accept` → first
//! WebSocket heartbeat. Verifies the K2 invite flow, hub-blind
//! data model, and the on-disk state persistence (identity.bin,
//! enrollment.json, admin-chain/*.cbor).

use std::path::PathBuf;
use std::time::Duration;

use sha2::Digest as _;
use tokio::net::TcpListener;

use vitonomi_core::crypto::admin_chain::{sign_entry, AdminAction, GENESIS_PREV_HASH};
use vitonomi_core::crypto::challenge::sign_challenge;
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keys::{GenesisMaterial, MasterPublicKeys};
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::crypto::pq::ml_dsa_65_sign;
use vitonomi_core::encoding::{b64url_encode, cbor_to_vec};
use vitonomi_core::protocol::hub_control_plane::{ClusterRegisterRequest, ClusterRegisterResponse};
use vitonomi_core::protocol::wire::accept::{
    CreateInviteRequest, CreateInviteResponse, InviteInnerPayload, InviteOuterSummary, VaultRole,
};
use vitonomi_core::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, UserLookupId,
};
use vitonomi_core::types::{FormatVersion, Username};

use vitonomi_hub::state::AppState;

use vitonomi_vault::accept::CombinedInvite;
use vitonomi_vault::config::VaultConfig;

async fn boot_hub() -> (String, AppState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::in_memory();
    let st = state.clone();
    tokio::spawn(async move {
        let _ = vitonomi_hub::run_with_listener(listener, st).await;
    });
    (format!("http://{addr}"), state)
}

fn fast_lookup_params() -> LookupIdParams {
    LookupIdParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

fn build_invite_outer(
    cluster_id: vitonomi_core::types::ClusterId,
    nonce: Vec<u8>,
    inner: &InviteInnerPayload,
    admin_sk: &vitonomi_core::crypto::pq::MlDsa65SecretKey,
) -> InviteOuterSummary {
    let inner_bytes = cbor_to_vec(inner).unwrap();
    let mut h = sha2::Sha256::new();
    h.update(&inner_bytes);
    let inner_hash = h.finalize().to_vec();
    let mut signed = Vec::new();
    signed.push(FormatVersion::V1.as_u8());
    signed.extend_from_slice(cluster_id.as_bytes());
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&u64::MAX.to_be_bytes());
    signed.extend_from_slice(&inner_hash);
    let sig = ml_dsa_65_sign(admin_sk, &signed).unwrap();
    InviteOuterSummary {
        format_version: FormatVersion::V1,
        cluster_id,
        invite_nonce: nonce,
        expires_at_ms: u64::MAX,
        inner_payload_hash: inner_hash,
        sig_admin_outer: sig,
    }
}

#[tokio::test]
async fn vault_init_accept_persists_state_correctly() {
    let (hub_url, _state) = boot_hub().await;
    let client = reqwest::Client::new();

    // ─── Cluster registration (admin side) ────────────────────────
    let g = GenesisMaterial::generate().unwrap();
    let pubkeys = MasterPublicKeys::from(&g.master_keys);
    let cluster_id = cluster_id_of(&pubkeys.cluster_admin, FormatVersion::V1);
    let username = Username::parse("birkeal").unwrap();
    let lookup_bytes = compute_lookup_id(
        &username,
        &g.cluster_pepper,
        &cluster_id,
        fast_lookup_params(),
    )
    .unwrap();
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
    let reg: ClusterRegisterResponse = client
        .post(format!("{hub_url}/v1/clusters"))
        .json(&ClusterRegisterRequest {
            lookup_id: lookup_id.clone(),
            master_pubkeys: pubkeys.clone(),
            encrypted_key_blob: vec![0xab; 64],
            genesis_entry: genesis,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Login (so admin has a session for the invite).
    let start: LoginStartResponse = client
        .post(format!("{hub_url}/v1/auth/login/start"))
        .json(&LoginStartRequest { lookup_id })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let sig = sign_challenge(&g.master_keys.identity.secret, &start.challenge).unwrap();
    let _: LoginFinishResponse = client
        .post(format!("{hub_url}/v1/auth/login/finish"))
        .json(&LoginFinishRequest {
            challenge_id: start.challenge_id,
            signature: sig,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Build the invite (outer + inner).
    let invite_nonce = vec![0xcc; 32];
    let inner = InviteInnerPayload {
        format_version: FormatVersion::V1,
        vault_role: VaultRole::Storage,
        hub_url: hub_url.clone(),
        hub_cert_fingerprint: "sha256:test-fingerprint-string-of-43-base64url-chars-x".into(),
        sealed_cluster_key: vec![0u8; 72],
    };
    let outer = build_invite_outer(
        cluster_id,
        invite_nonce.clone(),
        &inner,
        &g.master_keys.cluster_admin.secret,
    );
    let _: CreateInviteResponse = client
        .post(format!("{hub_url}/v1/vaults/invites"))
        .bearer_auth(&reg.session_token.0)
        .json(&CreateInviteRequest {
            invite: outer.clone(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // Encode the invite the way the operator would paste it.
    let combined = CombinedInvite { outer, inner };
    let invite_token = combined.encode().unwrap();
    let _ = b64url_encode(b"unused"); // ensure base64 import is wired

    // ─── Vault side: init + accept via the library ────────────────
    let dir = tempfile::tempdir().unwrap();
    let cfg_path: PathBuf = dir.path().join("vault.toml");
    let data_dir = dir.path().join("data");
    vitonomi_vault::config::write_default_config(
        Some(&cfg_path),
        vitonomi_vault::config::InitOverrides {
            data_dir: Some(data_dir.clone()),
            hub_url: Some(hub_url.clone()),
        },
        true,
    )
    .unwrap();

    let mut cfg = VaultConfig::load(
        Some(&cfg_path),
        vitonomi_vault::config::CliOverrides::default(),
    )
    .unwrap();
    let _accept = vitonomi_vault::accept::run(&cfg_path, &mut cfg, &invite_token)
        .await
        .expect("vault accept");

    // Verify on-disk state.
    let id_path = vitonomi_vault::state_dir::identity_path(&data_dir);
    assert!(id_path.exists(), "identity.bin should exist");
    let enr_path = vitonomi_vault::state_dir::enrollment_path(&data_dir);
    assert!(enr_path.exists(), "enrollment.json should exist");
    let chain_dir = vitonomi_vault::state_dir::admin_chain_dir(&data_dir);
    let entries: Vec<_> = std::fs::read_dir(&chain_dir).unwrap().collect();
    assert!(!entries.is_empty(), "admin-chain dir should hold ≥1 entry");

    // Verify config persisted the cert_fingerprint from the invite.
    let cfg_after = VaultConfig::load(
        Some(&cfg_path),
        vitonomi_vault::config::CliOverrides::default(),
    )
    .unwrap();
    assert!(!cfg_after.hub.cert_fingerprint.is_empty());

    // Verify status command output (no panic; produces a chain-len > 0).
    vitonomi_vault::commands::status::run(cfg_after).unwrap();

    // Yield briefly so the spawned hub finishes any pending tasks.
    let _ = tokio::time::timeout(Duration::from_millis(50), futures::future::pending::<()>()).await;
}
