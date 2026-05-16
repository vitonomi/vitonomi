//! Hub control-plane tests for the alias directory: signed publish,
//! public lookup, and signature-tampering rejection.

mod common;

use vitonomi_core::crypto::pq::ml_kem_768_keypair;
use vitonomi_core::errors::CoreError;
use vitonomi_core::protocol::hub_control_plane::HubControlPlane;
use vitonomi_core::record::RecordId;

use common::{bootstrap_user, signed_alias_entry};

#[tokio::test]
async fn alias_directory_publish_and_lookup_round_trip() {
    let (hub, token, identity_kp, _) = bootstrap_user("birkeal").await;
    let kem = ml_kem_768_keypair().unwrap();
    let alias_id = RecordId([7u8; 16]);
    let entry = signed_alias_entry(
        "netflix",
        "inbox-demo.vito.gg",
        alias_id,
        &kem.public,
        &identity_kp,
    );
    hub.publish_alias_pubkey(&token, entry.clone())
        .await
        .expect("publish");
    let back = hub
        .lookup_alias_pubkey("netflix", "inbox-demo.vito.gg")
        .await
        .expect("lookup");
    assert_eq!(back, entry);
}

#[tokio::test]
async fn alias_directory_rejects_bad_signature() {
    let (hub, token, identity_kp, _) = bootstrap_user("birkeal").await;
    let kem = ml_kem_768_keypair().unwrap();
    let alias_id = RecordId([7u8; 16]);
    let mut entry = signed_alias_entry(
        "netflix",
        "inbox-demo.vito.gg",
        alias_id,
        &kem.public,
        &identity_kp,
    );
    entry.alias_handle = "tampered".into();
    let err = hub.publish_alias_pubkey(&token, entry).await.unwrap_err();
    assert!(matches!(err, CoreError::Protocol(_)));
}
