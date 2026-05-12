//! End-to-end test for the data-plane libp2p path.
//!
//! Boots the vault libp2p Swarm (server side) backed by a real
//! `SqliteVaultStorage`, dials it from a CLI-side libp2p client, and
//! drives a full `RecordStore` put / get / list / delete round-trip
//! through `Libp2pChunkTransport` + `LocalHeadStore`.
//!
//! Skips the hub entirely — the hub's role in slice 3 is just
//! introducing the multiaddr (which we hand to the client directly
//! here) and serving public user-pubkey lookups (which we wire via an
//! in-test fixed resolver). The control-plane handshake is already
//! covered by `mini_mvp.rs`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use vitonomi_cli::commands::local_head_store::LocalHeadStore;
use vitonomi_cli::p2p::{dial_vault, load_or_generate_libp2p_key, Libp2pChunkTransport};

use vitonomi_core::crypto::keys::MasterKeys;
use vitonomi_core::crypto::pq::MlDsa65PublicKey;
use vitonomi_core::record::record_store::{RecordStore, UserKeys};
use vitonomi_core::record::user_keys::derive_user_aead_master;
use vitonomi_core::record::RecordType;
use vitonomi_core::types::{ClusterId, UserId};

use vitonomi_vault::p2p::{load_or_generate_transport_keypair, IdentityResolver, P2pNode};
use vitonomi_vault::storage::SqliteVaultStorage;

/// In-test `IdentityResolver` that hands the vault the user's identity
/// pubkey directly — no hub round-trip needed for this test.
struct FixedResolver {
    cid: ClusterId,
    uid: UserId,
    pk: MlDsa65PublicKey,
}

#[async_trait]
impl IdentityResolver for FixedResolver {
    async fn lookup(
        &self,
        cluster_id: &ClusterId,
        user_id: &UserId,
    ) -> Result<MlDsa65PublicKey, anyhow::Error> {
        if cluster_id == &self.cid && user_id == &self.uid {
            Ok(self.pk.clone())
        } else {
            anyhow::bail!("unknown user")
        }
    }
}

async fn fixture_user_keys() -> (UserKeys, MasterKeys) {
    let mk = MasterKeys::generate().unwrap();
    let phrase = vitonomi_core::crypto::seedphrase::SeedPhrase::generate().unwrap();
    let seed = phrase.to_seed("");
    let master = derive_user_aead_master(&seed);
    let user_id = UserId([42u8; 16]);
    let cluster_id = ClusterId([7u8; 32]);
    let keys = UserKeys {
        user_id,
        cluster_id,
        identity_pk: mk.identity.public.clone(),
        identity_sk: vitonomi_core::crypto::pq::MlDsa65SecretKey(mk.identity.secret.0.clone()),
        user_aead_master: master,
    };
    (keys, mk)
}

async fn wait_for_first_addr(
    rx: &mut tokio::sync::watch::Receiver<Vec<libp2p::Multiaddr>>,
) -> libp2p::Multiaddr {
    for _ in 0..40 {
        let cur = rx.borrow().clone();
        if let Some(addr) = cur.into_iter().find(|m| m.to_string().contains("/tcp/")) {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("vault never advertised a TCP multiaddr");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_get_round_trip_via_libp2p() {
    let vault_dir = tempfile::tempdir().unwrap();
    let cli_dir = tempfile::tempdir().unwrap();

    let (user_keys, _master_keys) = fixture_user_keys().await;

    // ── Vault side ─────────────────────────────────────────────
    let vault_transport_kp = load_or_generate_transport_keypair(vault_dir.path()).unwrap();
    let storage = Arc::new(
        SqliteVaultStorage::open(vault_dir.path())
            .await
            .expect("open SqliteVaultStorage"),
    );
    let resolver = Arc::new(FixedResolver {
        cid: user_keys.cluster_id,
        uid: user_keys.user_id,
        pk: user_keys.identity_pk.clone(),
    });
    let p2p_handle = P2pNode::spawn(
        vault_transport_kp,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        storage as Arc<dyn vitonomi_core::protocol::vault_storage::VaultStorage>,
        resolver,
    )
    .await
    .expect("spawn vault P2pNode");

    let mut rx = p2p_handle.multiaddrs.clone();
    let vault_addr = wait_for_first_addr(&mut rx).await;

    // ── CLI side ───────────────────────────────────────────────
    let cli_kp = load_or_generate_libp2p_key(cli_dir.path()).unwrap();
    let client_handle = dial_vault(cli_kp, vault_addr.clone())
        .await
        .expect("dial vault");
    let client_handle = Arc::new(client_handle);

    let identity_sk_clone =
        vitonomi_core::crypto::pq::MlDsa65SecretKey(user_keys.identity_sk.0.clone());
    let chunk_transport = Libp2pChunkTransport::new(
        client_handle.clone(),
        user_keys.cluster_id,
        user_keys.user_id,
        identity_sk_clone,
    );
    let head_store = LocalHeadStore::new(cli_dir.path()).unwrap();
    let record_store = RecordStore::new(user_keys, chunk_transport, head_store);

    // ── Round-trip: put → get ───────────────────────────────────
    let plaintext = b"credential payload: pw=hunter2";
    let id = record_store
        .put(RecordType::Credential, plaintext)
        .await
        .expect("put credential");
    let got = record_store
        .get(RecordType::Credential, id)
        .await
        .expect("get credential")
        .expect("present");
    assert_eq!(got, plaintext, "round-trip plaintext must match");

    // List returns the one record.
    let listed = record_store
        .list(RecordType::Credential)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, id);
    assert_eq!(listed[0].1.as_slice(), plaintext);

    // ── Shutdown ────────────────────────────────────────────────
    if let Ok(handle) = Arc::try_unwrap(client_handle) {
        handle.shutdown().await;
    }
    let _ = p2p_handle.shutdown.send(()).await;
    let _ = p2p_handle.join.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_then_delete_via_libp2p() {
    let vault_dir = tempfile::tempdir().unwrap();
    let cli_dir = tempfile::tempdir().unwrap();
    let (user_keys, _) = fixture_user_keys().await;

    let vault_kp = load_or_generate_transport_keypair(vault_dir.path()).unwrap();
    let storage = Arc::new(SqliteVaultStorage::open(vault_dir.path()).await.unwrap());
    let resolver = Arc::new(FixedResolver {
        cid: user_keys.cluster_id,
        uid: user_keys.user_id,
        pk: user_keys.identity_pk.clone(),
    });
    let p2p_handle = P2pNode::spawn(
        vault_kp,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        storage as Arc<dyn vitonomi_core::protocol::vault_storage::VaultStorage>,
        resolver,
    )
    .await
    .unwrap();
    let mut rx = p2p_handle.multiaddrs.clone();
    let vault_addr = wait_for_first_addr(&mut rx).await;

    let cli_kp = load_or_generate_libp2p_key(cli_dir.path()).unwrap();
    let client_handle = Arc::new(dial_vault(cli_kp, vault_addr).await.unwrap());
    let chunk_transport = Libp2pChunkTransport::new(
        client_handle.clone(),
        user_keys.cluster_id,
        user_keys.user_id,
        vitonomi_core::crypto::pq::MlDsa65SecretKey(user_keys.identity_sk.0.clone()),
    );
    let head_store = LocalHeadStore::new(cli_dir.path()).unwrap();
    let record_store = RecordStore::new(user_keys, chunk_transport, head_store);

    let a = record_store
        .put(RecordType::Credential, b"first")
        .await
        .unwrap();
    let _b = record_store
        .put(RecordType::Credential, b"second")
        .await
        .unwrap();
    assert_eq!(
        record_store
            .list(RecordType::Credential)
            .await
            .unwrap()
            .len(),
        2
    );
    record_store
        .delete(RecordType::Credential, a)
        .await
        .unwrap();
    let after = record_store.list(RecordType::Credential).await.unwrap();
    assert_eq!(after.len(), 1);
    assert_ne!(after[0].0, a);

    if let Ok(handle) = Arc::try_unwrap(client_handle) {
        handle.shutdown().await;
    }
    let _ = p2p_handle.shutdown.send(()).await;
    let _ = p2p_handle.join.await;
}
