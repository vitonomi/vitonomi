//! Hub control-plane tests for `vitonomi-mx` relay identity
//! registration and the silent-drop semantics on unknown-alias
//! pushes from a registered mx relay.

mod common;

use vitonomi_core::crypto::alias_inbound::seal_to_alias;
use vitonomi_core::crypto::pq::{ml_dsa_65_keypair, ml_dsa_65_sign, ml_kem_768_keypair, MlDsa65Signature};
use vitonomi_core::protocol::hub_control_plane::HubControlPlane;
use vitonomi_core::protocol::wire::mx_relay_push::{
    MxRelayId, RegisterMxRelayRequest, SignedMxRelayPush,
};
use vitonomi_core::record::RecordId;

use common::bootstrap_user;

#[tokio::test]
async fn mx_relay_push_silent_drops_unknown_alias() {
    let (hub, token, _, _) = bootstrap_user("birkeal").await;
    let mx_relay_kp = ml_dsa_65_keypair().unwrap();
    hub.register_mx_relay_identity(
        &token,
        RegisterMxRelayRequest {
            mx_relay_pubkey: mx_relay_kp.public.clone(),
            allowed_namespaces: vec!["vito.gg".into()],
        },
    )
    .await
    .expect("register mx relay");
    let mx_relay_id = MxRelayId::from_pubkey(&mx_relay_kp.public);
    let alias_kp = ml_kem_768_keypair().unwrap();
    let envelope = seal_to_alias(&alias_kp.public, RecordId([0; 16]), 0, b"hi").unwrap();
    let mut push = SignedMxRelayPush {
        mx_relay_id,
        alias_directory_lookup: ("nonexistent".into(), "no.where".into()),
        envelope,
        server_received_at_ms: 0,
        sig_mx_relay: MlDsa65Signature(vec![]),
    };
    push.sig_mx_relay = ml_dsa_65_sign(&mx_relay_kp.secret, &push.signed_bytes().unwrap()).unwrap();
    let ack = hub.mx_relay_push_inbound(push).await.unwrap();
    assert!(!ack.received, "unknown alias should silent-drop");
}
