//! End-to-end smoke for the running hub binary. Spins up axum on
//! an ephemeral port, hits `/v1/status` and the cluster register +
//! login flow over real HTTP.

use sha2::Digest as _;
use tokio::net::TcpListener;
use vitonomi_core::crypto::admin_chain::{sign_entry, AdminAction, GENESIS_PREV_HASH};
use vitonomi_core::crypto::challenge::sign_challenge;
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keys::{GenesisMaterial, MasterPublicKeys};
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::protocol::hub_control_plane::{ClusterRegisterRequest, ClusterRegisterResponse};
use vitonomi_core::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, UserLookupId,
};
use vitonomi_core::types::{FormatVersion, Username};
use vitonomi_hub::state::AppState;

async fn boot_hub() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::in_memory();
    let handle = tokio::spawn(async move {
        let _ = vitonomi_hub::run_with_listener(listener, state).await;
    });
    (format!("http://{addr}"), handle)
}

fn fast_lookup_params() -> LookupIdParams {
    LookupIdParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

#[tokio::test]
async fn status_endpoint() {
    let (base, _h) = boot_hub().await;
    let resp = reqwest::get(format!("{base}/v1/status"))
        .await
        .expect("status get");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["version"].is_string());
}

#[tokio::test]
async fn register_then_login_round_trip() {
    let (base, _h) = boot_hub().await;
    let client = reqwest::Client::new();

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

    let reg_req = ClusterRegisterRequest {
        lookup_id: lookup_id.clone(),
        master_pubkeys: pubkeys.clone(),
        encrypted_key_blob: vec![0xab; 64],
        genesis_entry: genesis,
    };
    let reg: ClusterRegisterResponse = client
        .post(format!("{base}/v1/clusters"))
        .json(&reg_req)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reg.cluster_id, cluster_id);

    // Login start.
    let start: LoginStartResponse = client
        .post(format!("{base}/v1/auth/login/start"))
        .json(&LoginStartRequest {
            lookup_id: lookup_id.clone(),
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let _ = sha2::Sha256::new(); // ensure the trait import resolves

    // Login finish (sign the challenge with the identity sk).
    let sig = sign_challenge(&g.master_keys.identity.secret, &start.challenge).unwrap();
    let finish: LoginFinishResponse = client
        .post(format!("{base}/v1/auth/login/finish"))
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
    assert!(!finish.session_token.0.is_empty());
}
