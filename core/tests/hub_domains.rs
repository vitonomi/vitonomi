//! Hub control-plane tests for user-owned, DNS-verified domains.
//! Exercises `add_domain` → `verify_domain` → `list_domains`
//! lifecycle against the in-memory backend. The in-memory hub
//! short-circuits real DNS resolution and marks verified
//! unconditionally; the test asserts the state transition shape.

mod common;

use vitonomi_core::protocol::hub_control_plane::HubControlPlane;

use common::bootstrap_user;

#[tokio::test]
async fn add_then_verify_domain_marks_active() {
    let (hub, token, _, _) = bootstrap_user("birkeal").await;
    let challenge = hub
        .add_domain(&token, "example.com")
        .await
        .expect("add");
    assert!(!challenge.txt_record_value.is_empty());
    assert!(!challenge.required_mx_target.is_empty());
    let v = hub
        .verify_domain(&token, "example.com")
        .await
        .expect("verify");
    assert_eq!(v.domain, "example.com");
    let listed = hub.list_domains(&token).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].domain, "example.com");
}
