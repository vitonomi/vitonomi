//! Phase 7 Slice 5 tests — exercises the new HubControlPlane
//! surface (subdomains, custom domains, alias directory,
//! per-alias inbound queue, relay identity) against the
//! in-memory backend.

use sha2::Digest as _;

use vitonomi_core::crypto::admin_chain::{sign_entry, AdminAction, GENESIS_PREV_HASH};
use vitonomi_core::crypto::alias_inbound::seal_to_alias;
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keys::{GenesisMaterial, MasterPublicKeys};
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::crypto::pq::{
    ml_dsa_65_keypair, ml_dsa_65_sign, ml_kem_768_keypair, MlDsa65Keypair, MlDsa65Signature,
    MlKem768PublicKey,
};
use vitonomi_core::encoding::cbor_to_vec;
use vitonomi_core::errors::{CoreError, ValidationError};
use vitonomi_core::protocol::hub_control_plane::{ClusterRegisterRequest, HubControlPlane};
use vitonomi_core::protocol::testing::in_memory_hub::InMemoryHubControlPlane;
use vitonomi_core::protocol::wire::aliases::AliasDirectoryEntry;
use vitonomi_core::protocol::wire::login::UserLookupId;
use vitonomi_core::protocol::wire::relay_push::{
    RegisterRelayRequest, SignedRelayPush,
};
use vitonomi_core::record::RecordId;
use vitonomi_core::types::subdomain::{Subdomain, SubdomainClaim};
use vitonomi_core::types::{ClusterId, FormatVersion, SessionToken, Username};

fn fast_lookup_params() -> LookupIdParams {
    LookupIdParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

/// Boot an in-memory hub + register one cluster + return the
/// session token plus the user's identity keypair (for signing
/// claims / alias-directory entries).
async fn bootstrap_user(
    username_str: &str,
) -> (InMemoryHubControlPlane, SessionToken, MlDsa65Keypair, ClusterId) {
    let hub = InMemoryHubControlPlane::new();
    let g = GenesisMaterial::generate().expect("genesis");
    let pubkeys = MasterPublicKeys::from(&g.master_keys);
    let cluster_id = cluster_id_of(&pubkeys.cluster_admin, FormatVersion::V1);
    let username = Username::parse(username_str).unwrap();
    let lookup_bytes =
        compute_lookup_id(&username, &g.cluster_pepper, &cluster_id, fast_lookup_params())
            .expect("lookup");
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
    let resp = hub
        .register_cluster(ClusterRegisterRequest {
            lookup_id,
            master_pubkeys: pubkeys,
            encrypted_key_blob: vec![0xab; 64],
            genesis_entry: genesis,
        })
        .await
        .expect("register cluster");
    // The user's identity keypair lives in `g.master_keys.identity`.
    let identity = MlDsa65Keypair {
        public: g.master_keys.identity.public.clone(),
        secret: vitonomi_core::crypto::pq::MlDsa65SecretKey(
            g.master_keys.identity.secret.0.clone(),
        ),
    };
    (hub, resp.session_token, identity, cluster_id)
}

fn make_claim(sub: &str, base: &str, kp: &MlDsa65Keypair) -> SubdomainClaim {
    let s = Subdomain::parse(sub).unwrap();
    let mut claim = SubdomainClaim {
        format_version: FormatVersion::V1,
        subdomain: s,
        base_domain: base.into(),
        user_identity_pubkey: kp.public.clone(),
        claimed_at_ms: 1_700_000_000_000,
        sig_user: MlDsa65Signature(vec![]),
    };
    let msg = claim.to_signed_bytes().unwrap();
    claim.sig_user = ml_dsa_65_sign(&kp.secret, &msg).unwrap();
    claim
}

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
    // Exercise that defense: deserialize a reserved name
    // straight from a JSON string and post it to the hub.
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

#[tokio::test]
async fn relay_push_silent_drops_unknown_alias() {
    let (hub, token, _, _) = bootstrap_user("birkeal").await;
    let relay_kp = ml_dsa_65_keypair().unwrap();
    let resp = hub
        .register_relay_identity(
            &token,
            RegisterRelayRequest {
                relay_pubkey: relay_kp.public.clone(),
                allowed_namespaces: vec!["vito.gg".into()],
            },
        )
        .await
        .expect("register relay");
    let alias_kp = ml_kem_768_keypair().unwrap();
    let envelope = seal_to_alias(&alias_kp.public, RecordId([0; 16]), 0, b"hi").unwrap();
    let mut push = SignedRelayPush {
        relay_id: resp.relay_id,
        alias_directory_lookup: ("nonexistent".into(), "no.where".into()),
        envelope,
        server_received_at_ms: 0,
        sig_relay: MlDsa65Signature(vec![]),
    };
    push.sig_relay = ml_dsa_65_sign(&relay_kp.secret, &push.signed_bytes().unwrap()).unwrap();
    let ack = hub.relay_push_inbound(push).await.unwrap();
    assert!(!ack.received, "unknown alias should silent-drop");
}

#[tokio::test]
async fn inbox_fifo_in_seq_order_and_ack_drops_envelopes() {
    let (hub, token, identity_kp, _) = bootstrap_user("birkeal").await;
    let relay_kp = ml_dsa_65_keypair().unwrap();
    let resp = hub
        .register_relay_identity(
            &token,
            RegisterRelayRequest {
                relay_pubkey: relay_kp.public.clone(),
                allowed_namespaces: vec!["vito.gg".into()],
            },
        )
        .await
        .expect("register relay");
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
        let mut push = SignedRelayPush {
            relay_id: resp.relay_id,
            alias_directory_lookup: ("drop".into(), "inbox-demo.vito.gg".into()),
            envelope,
            server_received_at_ms: i,
            sig_relay: MlDsa65Signature(vec![]),
        };
        push.sig_relay =
            ml_dsa_65_sign(&relay_kp.secret, &push.signed_bytes().unwrap()).unwrap();
        let ack = hub.relay_push_inbound(push).await.unwrap();
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

#[tokio::test]
async fn add_then_verify_custom_domain_marks_active() {
    let (hub, token, _, _) = bootstrap_user("birkeal").await;
    let challenge = hub
        .add_custom_domain(&token, "example.com")
        .await
        .expect("add");
    assert!(!challenge.txt_record_value.is_empty());
    assert!(!challenge.required_mx_target.is_empty());
    let v = hub
        .verify_custom_domain(&token, "example.com")
        .await
        .expect("verify");
    assert_eq!(v.domain, "example.com");
    let listed = hub.list_custom_domains(&token).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].domain, "example.com");
}

#[tokio::test]
async fn list_managed_base_domains_returns_vito_gg_default() {
    let hub = InMemoryHubControlPlane::new();
    let bases = hub.list_managed_base_domains().await.unwrap();
    assert_eq!(bases, vec!["vito.gg"]);
}

// ── helpers ─────────────────────────────────────────────────

fn signed_alias_entry(
    alias_handle: &str,
    namespace: &str,
    alias_id: RecordId,
    alias_kem_pubkey: &MlKem768PublicKey,
    user_identity_kp: &MlDsa65Keypair,
) -> AliasDirectoryEntry {
    let signed = (
        &alias_handle.to_string(),
        &namespace.to_string(),
        &alias_id,
        alias_kem_pubkey,
    );
    let msg = cbor_to_vec(&signed).unwrap();
    let sig = ml_dsa_65_sign(&user_identity_kp.secret, &msg).unwrap();
    AliasDirectoryEntry {
        alias_handle: alias_handle.into(),
        namespace: namespace.into(),
        alias_id,
        alias_kem_pubkey: alias_kem_pubkey.clone(),
        user_identity_pubkey: user_identity_kp.public.clone(),
        sig_user: sig,
    }
}

#[tokio::test]
async fn _suppress_unused_warning_for_sha2() {
    // sha2 is used transitively by GenesisMaterial; this stub
    // ensures the unused import warning doesn't trip when the
    // bootstrap helper changes.
    let _ = sha2::Sha256::new();
}
