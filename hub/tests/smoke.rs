//! End-to-end smoke for the running hub binary. Spins up axum on
//! an ephemeral port, hits `/v1/status`, runs the full Scheme A
//! login round trip, accepts a vault via the K2 invite flow, and
//! drives the WebSocket vault-bus handshake (challenge / response /
//! session-established / heartbeat) over real TCP.

use futures::{SinkExt as _, StreamExt as _};
use sha2::Digest as _;
use tokio::net::TcpListener;

use vitonomi_core::crypto::admin_chain::{
    sign_entry, AdminAction, AdminChainEntry, GENESIS_PREV_HASH,
};
use vitonomi_core::crypto::challenge::sign_challenge;
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keys::{GenesisMaterial, MasterPublicKeys};
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::crypto::pq::{ml_dsa_65_keypair, ml_dsa_65_sign};
use vitonomi_core::encoding::{cbor_from_slice, cbor_to_vec};
use vitonomi_core::protocol::hub_control_plane::{ClusterRegisterRequest, ClusterRegisterResponse};
use vitonomi_core::protocol::wire::accept::{
    AcceptRequest, AcceptResponse, CreateInviteRequest, CreateInviteResponse, InviteInnerPayload,
    InviteOuterSummary, VaultRole,
};
use vitonomi_core::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse, UserLookupId,
};
use vitonomi_core::protocol::wire::vault_bus::{BusFrame, ChallengeResponseFrame, HeartbeatFrame};
use vitonomi_core::types::{FormatVersion, Username};
use vitonomi_hub::state::AppState;

async fn boot_hub() -> (String, tokio::task::JoinHandle<()>, AppState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::in_memory();
    let state_clone = state.clone();
    let handle = tokio::spawn(async move {
        let _ = vitonomi_hub::run_with_listener(listener, state_clone).await;
    });
    (format!("http://{addr}"), handle, state)
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
    let (base, _h, _s) = boot_hub().await;
    let resp = reqwest::get(format!("{base}/v1/status"))
        .await
        .expect("status get");
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert!(body["version"].is_string());
}

#[tokio::test]
async fn full_register_login_invite_accept_ws_round_trip() {
    let (base, _h, _state) = boot_hub().await;
    let client = reqwest::Client::new();

    // 1. Generate cluster material.
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

    // 2. Register cluster.
    let reg: ClusterRegisterResponse = client
        .post(format!("{base}/v1/clusters"))
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

    // 3. Login round trip.
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
    let sig = sign_challenge(&g.master_keys.identity.secret, &start.challenge).unwrap();
    let _finish: LoginFinishResponse = client
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

    // 4. Build + register an invite (admin signs outer locally).
    let invite_nonce = vec![0xcc; 32];
    let inner = InviteInnerPayload {
        format_version: FormatVersion::V1,
        vault_role: VaultRole::Storage,
        hub_url: base.clone(),
        hub_cert_fingerprint: "sha256:test-fingerprint-string-of-43-base64url-chars-x".into(),
        sealed_cluster_key: vec![0u8; 72],
    };
    let inner_bytes = cbor_to_vec(&inner).unwrap();
    let inner_hash = {
        let mut h = sha2::Sha256::new();
        h.update(&inner_bytes);
        h.finalize().to_vec()
    };
    let outer_unsigned = {
        let mut buf = Vec::new();
        buf.push(FormatVersion::V1.as_u8());
        buf.extend_from_slice(cluster_id.as_bytes());
        buf.extend_from_slice(&invite_nonce);
        buf.extend_from_slice(&u64::MAX.to_be_bytes());
        buf.extend_from_slice(&inner_hash);
        buf
    };
    let sig_admin_outer =
        ml_dsa_65_sign(&g.master_keys.cluster_admin.secret, &outer_unsigned).unwrap();
    let outer = InviteOuterSummary {
        format_version: FormatVersion::V1,
        cluster_id,
        invite_nonce: invite_nonce.clone(),
        expires_at_ms: u64::MAX,
        inner_payload_hash: inner_hash,
        sig_admin_outer,
    };

    let _: CreateInviteResponse = client
        .post(format!("{base}/v1/vaults/invites"))
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

    // 5. Vault generates keypair, signs accept, posts.
    let vault_kp = ml_dsa_65_keypair().unwrap();
    let mut signed = invite_nonce.clone();
    signed.extend_from_slice(vault_kp.public.as_bytes());
    let sig_vault = ml_dsa_65_sign(&vault_kp.secret, &signed).unwrap();
    let accept: AcceptResponse = client
        .post(format!("{base}/v1/vaults/accept"))
        .json(&AcceptRequest {
            invite_outer: outer,
            invite_inner: inner,
            vault_pubkey: vault_kp.public.clone(),
            sig_vault,
        })
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    // 6. WS handshake: connect, recv Challenge, send ChallengeResponse,
    //    recv SessionEstablished, send Heartbeat.
    let ws_url = base.replacen("http://", "ws://", 1) + "/v1/vault-bus";
    let mut req = ws_url.into_client_request().expect("build ws request");
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "vitonomi.vault-bus.v1".parse().unwrap(),
    );
    let (mut socket, _resp) = tokio_tungstenite::connect_async(req)
        .await
        .expect("ws connect");

    // Recv Challenge.
    let frame = recv_bus_frame(&mut socket).await;
    let challenge_frame = match frame {
        BusFrame::Challenge(c) => c,
        other => panic!("expected Challenge, got {other:?}"),
    };

    // Sign + send ChallengeResponse.
    let sig = sign_challenge(&vault_kp.secret, &challenge_frame.challenge).unwrap();
    send_bus_frame(
        &mut socket,
        &BusFrame::ChallengeResponse(ChallengeResponseFrame {
            vault_id: accept.vault_id,
            signature: sig,
        }),
    )
    .await;

    // Recv SessionEstablished — confirms the hub verified our sig.
    let frame = recv_bus_frame(&mut socket).await;
    let session_frame = match frame {
        BusFrame::SessionEstablished(s) => s,
        other => panic!("expected SessionEstablished, got {other:?}"),
    };
    assert!(!session_frame.session_id.is_empty());

    // Send a heartbeat (signed). Server verifies + updates last_seen.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut hb_signed = Vec::new();
    hb_signed.extend_from_slice(&accept.vault_id.0);
    hb_signed.extend_from_slice(&now_ms.to_be_bytes());
    let hb_sig = ml_dsa_65_sign(&vault_kp.secret, &hb_signed).unwrap();
    send_bus_frame(
        &mut socket,
        &BusFrame::Heartbeat(HeartbeatFrame {
            vault_id: accept.vault_id,
            ts_ms: now_ms,
            signature: hb_sig,
        }),
    )
    .await;

    // Drain briefly then close.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(100), socket.next()).await;
    let _ = socket.close(None).await;
}

// Helpers for length-prefixed CBOR over WS.
async fn send_bus_frame(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    frame: &BusFrame,
) {
    let cbor = cbor_to_vec(frame).unwrap();
    let len = u32::try_from(cbor.len()).unwrap();
    let mut buf = Vec::with_capacity(4 + cbor.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&cbor);
    socket
        .send(tokio_tungstenite::tungstenite::Message::Binary(buf.into()))
        .await
        .unwrap();
}

async fn recv_bus_frame(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> BusFrame {
    let msg = socket.next().await.expect("ws msg").expect("ws msg ok");
    let bytes = match msg {
        tokio_tungstenite::tungstenite::Message::Binary(b) => b,
        other => panic!("expected binary, got {other:?}"),
    };
    assert!(bytes.len() >= 4, "frame too short");
    let len_arr: [u8; 4] = bytes[..4].try_into().unwrap();
    let len = u32::from_le_bytes(len_arr) as usize;
    assert_eq!(bytes.len(), 4 + len, "len prefix mismatch");
    cbor_from_slice(&bytes[4..]).expect("decode bus frame")
}

use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
