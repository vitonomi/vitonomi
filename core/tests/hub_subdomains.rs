//! Hub HTTP/control-plane tests for managed-subdomain claims under
//! a hub-managed base. Exercises `claim_subdomain`,
//! `lookup_subdomain`, and `list_managed_base_domains` against the
//! in-memory backend.

mod common;

use vitonomi_core::crypto::pq::{ml_dsa_65_sign, MlDsa65Signature};
use vitonomi_core::errors::{CoreError, ValidationError};
use vitonomi_core::protocol::hub_control_plane::HubControlPlane;
use vitonomi_core::protocol::testing::in_memory_hub::InMemoryHubControlPlane;
use vitonomi_core::types::subdomain::{Subdomain, SubdomainClaim};
use vitonomi_core::types::FormatVersion;

use common::{bootstrap_user, make_claim};

#[tokio::test]
async fn claim_subdomain_happy_path() {
    let (hub, token, kp, _) = bootstrap_user("birkeal").await;
    let claim = make_claim("inbox-demo", "vito.gg", &kp);
    hub.claim_subdomain(&token, claim).await.expect("claim");
    let entry = hub
        .lookup_subdomain("vito.gg", &Subdomain::parse("inbox-demo").unwrap())
        .await
        .expect("lookup");
    assert_eq!(entry.subdomain.as_str(), "inbox-demo");
    assert_eq!(entry.base_domain, "vito.gg");
}

#[tokio::test]
async fn claim_subdomain_rejects_reserved() {
    let (hub, token, kp, _) = bootstrap_user("birkeal").await;
    // `Subdomain::parse` already rejects reserved names — the
    // hub-side reserved check is defense-in-depth against a
    // malicious peer that bypasses `parse` via direct serde
    // construction (`Subdomain` is `#[serde(transparent)]`).
    // Exercise that defense: deserialize a reserved name straight
    // from a JSON string and post it to the hub.
    let bad_sub: Subdomain = serde_json::from_str("\"admin\"").unwrap();
    let mut claim = SubdomainClaim {
        format_version: FormatVersion::V1,
        subdomain: bad_sub,
        base_domain: "vito.gg".into(),
        user_identity_pubkey: kp.public.clone(),
        claimed_at_ms: 0,
        sig_user: MlDsa65Signature(vec![]),
    };
    let msg = claim.to_signed_bytes().unwrap();
    claim.sig_user = ml_dsa_65_sign(&kp.secret, &msg).unwrap();
    let err = hub.claim_subdomain(&token, claim).await.unwrap_err();
    assert!(
        matches!(err, CoreError::Validation(ValidationError::SubdomainReserved(_))),
        "expected SubdomainReserved, got {err:?}"
    );
}

#[tokio::test]
async fn claim_subdomain_rejects_taken_in_same_cluster() {
    let (hub, token, kp, _) = bootstrap_user("birkeal").await;
    let claim = make_claim("inbox-demo", "vito.gg", &kp);
    hub.claim_subdomain(&token, claim.clone())
        .await
        .expect("first claim");
    // Same user, second claim under same base → rejected.
    let err = hub.claim_subdomain(&token, claim).await.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("subdomain.taken") || msg.contains("subdomain.cluster_already"),
        "expected taken/cluster_already, got {msg}"
    );
}

#[tokio::test]
async fn claim_subdomain_rejects_invalid_signature() {
    let (hub, token, kp, _) = bootstrap_user("birkeal").await;
    let mut claim = make_claim("inbox-demo", "vito.gg", &kp);
    // Tamper: re-sign for a different subdomain, then put the
    // valid sig on a record whose subdomain field has changed.
    claim.subdomain = Subdomain::parse("inbox-other").unwrap();
    let err = hub.claim_subdomain(&token, claim).await.unwrap_err();
    assert!(
        matches!(err, CoreError::Protocol(_)),
        "expected ProtocolError on bad sig, got {err:?}"
    );
}

#[tokio::test]
async fn list_managed_base_domains_returns_default_on_init() {
    let hub = InMemoryHubControlPlane::new();
    let bases = hub.list_managed_base_domains().await.unwrap();
    assert_eq!(bases, vec!["vito.gg"]);
}
