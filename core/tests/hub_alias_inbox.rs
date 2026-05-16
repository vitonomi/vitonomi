//! Hub control-plane tests for the per-alias inbox FIFO: ordered
//! delivery, cursor-based fetch, and ack-driven GC. Cross-cuts the
//! mx-relay push surface (an mx-relay push appends to the inbox)
//! but the assertions here are about queue mechanics.

mod common;

use vitonomi_core::crypto::alias_inbound::seal_to_alias;
use vitonomi_core::crypto::pq::{ml_dsa_65_keypair, ml_dsa_65_sign, ml_kem_768_keypair, MlDsa65Signature};
use vitonomi_core::protocol::hub_control_plane::HubControlPlane;
use vitonomi_core::protocol::wire::mx_relay_push::{
    MxRelayId, RegisterMxRelayRequest, SignedMxRelayPush,
};
use vitonomi_core::record::RecordId;

use common::{bootstrap_user, signed_alias_entry};

#[tokio::test]
async fn inbox_fifo_in_seq_order_and_ack_drops_envelopes() {
    let (hub, token, identity_kp, _) = bootstrap_user("birkeal").await;
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
    let kem = ml_kem_768_keypair().unwrap();
    let alias_id = RecordId([0x42; 16]);
    let entry = signed_alias_entry(
        "drop",
        "inbox-demo.vito.gg",
        alias_id,
        &kem.public,
        &identity_kp,
    );
    hub.publish_alias_pubkey(&token, entry).await.unwrap();

    // Push 3 envelopes.
    for i in 0..3 {
        let envelope = seal_to_alias(
            &kem.public,
            alias_id,
            i,
            format!("msg-{i}").as_bytes(),
        )
        .unwrap();
        let mut push = SignedMxRelayPush {
            mx_relay_id,
            alias_directory_lookup: ("drop".into(), "inbox-demo.vito.gg".into()),
            envelope,
            server_received_at_ms: i,
            sig_mx_relay: MlDsa65Signature(vec![]),
        };
        push.sig_mx_relay =
            ml_dsa_65_sign(&mx_relay_kp.secret, &push.signed_bytes().unwrap()).unwrap();
        let ack = hub.mx_relay_push_inbound(push).await.unwrap();
        assert!(ack.received);
    }

    // Fetch all (since=0 returns seq>0).
    let all = hub.fetch_alias_inbox(&token, &alias_id, 0).await.unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].seq, 1);
    assert_eq!(all[2].seq, 3);

    // Cursor since=2 returns just seq=3.
    let after = hub.fetch_alias_inbox(&token, &alias_id, 2).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].seq, 3);

    // Ack up to seq=2 → fetch since=0 returns only seq>2.
    hub.ack_alias_inbox(&token, &alias_id, 2).await.unwrap();
    let after_ack = hub.fetch_alias_inbox(&token, &alias_id, 0).await.unwrap();
    assert_eq!(after_ack.len(), 1);
    assert_eq!(after_ack[0].seq, 3);
}
