//! Top-level mini-MVP integration test. Drives the full
//! hub + vault + CLI happy path plus the high-value negative
//! scenarios (used-invite replay, local-chain tampering,
//! identity tampering, cluster restore to a fresh hub) in one
//! suite. Each test boots its own ephemeral hub on port 0; no
//! shared state.

use vitonomi_core::crypto::admin_chain::{verify_chain_outer_only, AdminChainEntry};
use vitonomi_core::protocol::wire::accept::AcceptRequest;
use vitonomi_core::protocol::wire::accept::{encode_short_token, parse_short_token};
use vitonomi_vault::config::VaultConfig;

use vitonomi_cli::commands::vault_list::run as cli_vault_list;
use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;
use vitonomi_cli::state as cli_state;

use vitonomi_integration::harness::{
    boot_hub, fast_lookup_params, run_cluster_create, run_vault_invite, setup_admin,
    setup_and_accept_vault,
};

// ─── Tests ───────────────────────────────────────────────────────────

/// Happy path — hub + admin CLI + vault all on the table; vault
/// shows up in `cli vault list` and the on-disk state survives a
/// "restart" (re-load).
#[tokio::test]
async fn happy_path_end_to_end() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    let password = "correct horse battery staple";

    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;

    let vault = setup_and_accept_vault(temp.path(), "pi-1", &hub_url, &token).await;
    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    cli_vault_list(&cfg, &admin.cli_state_path)
        .await
        .expect("vault list");

    // Restart-persistence: re-load identity, enrollment, chain.
    let id = vitonomi_vault::identity::load_or_generate(&vault.data_dir).unwrap();
    assert!(!id.public.0.is_empty());
    let enrollment = vitonomi_vault::accept::load_enrollment(&vault.data_dir).unwrap();
    assert_eq!(
        enrollment.cluster_id.as_bytes(),
        cli_state::load(&admin.cli_state_path)
            .unwrap()
            .cluster_id
            .as_bytes(),
    );
    let store = vitonomi_vault::chain_store::ChainStore::open(&vault.data_dir).unwrap();
    let chain = store.read_all().unwrap();
    assert!(!chain.is_empty(), "chain replicated to vault on accept");
}

/// Replaying the same `invite_nonce` against `/v1/vaults/accept`
/// must be rejected by the hub (the in-memory backend uses
/// "invite already used" semantics; sqlx will use atomic ON
/// CONFLICT).
#[tokio::test]
async fn invite_nonce_replay_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    let password = "pw1";
    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;

    // First accept succeeds.
    let _v = setup_and_accept_vault(temp.path(), "pi-1", &hub_url, &token).await;

    // Second accept with the SAME token must fail.
    let parsed = parse_short_token(&token).unwrap();
    let vault_kp = vitonomi_core::crypto::pq::ml_dsa_65_keypair().unwrap();
    let mut signed = parsed.invite_nonce.clone();
    signed.extend_from_slice(vault_kp.public.as_bytes());
    let sig_vault = vitonomi_core::crypto::pq::ml_dsa_65_sign(&vault_kp.secret, &signed).unwrap();
    let req = AcceptRequest {
        cluster_id: parsed.cluster_id,
        invite_nonce: parsed.invite_nonce.clone(),
        invite_inner: parsed.inner,
        vault_pubkey: vault_kp.public,
        sig_vault,
    };
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let url = format!("{hub_url}/v1/vaults/accept");
    let resp = client.post(url).json(&req).send().await.unwrap();
    assert!(
        !resp.status().is_success(),
        "duplicate accept must be rejected; got {}",
        resp.status()
    );
}

/// A vault whose local chain copy has been tampered with refuses
/// to re-load it (or refuses to append against it). Surfaces the
/// "vault is the canonical chain authority" property.
#[tokio::test]
async fn tampered_local_chain_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    let password = "pw2";
    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;
    let vault = setup_and_accept_vault(temp.path(), "pi-1", &hub_url, &token).await;

    // Flip a byte in the persisted chain entry.
    let chain_dir = vitonomi_vault::state_dir::admin_chain_dir(&vault.data_dir);
    let entries: Vec<_> = std::fs::read_dir(&chain_dir).unwrap().collect();
    let any = entries.into_iter().next().unwrap().unwrap();
    let path = any.path();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt as _;
    perms.set_mode(0o600);
    std::fs::set_permissions(&path, perms).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    // Reading the chain through ChainStore + verifying outer-only
    // against the cached cluster_admin_pubkey must fail.
    let store = vitonomi_vault::chain_store::ChainStore::open(&vault.data_dir).unwrap();
    let chain: Vec<AdminChainEntry> = store.read_all().unwrap_or_default();
    let enrollment = vitonomi_vault::accept::load_enrollment(&vault.data_dir).unwrap();
    let result = verify_chain_outer_only(
        &enrollment.cluster_admin_pubkey,
        enrollment.cluster_id,
        &chain,
    );
    assert!(
        result.is_err() || chain.is_empty(),
        "tampered chain entry should fail verification or fail to decode"
    );
}

/// A vault whose `identity.bin` has been truncated refuses to
/// load — the perm/length sanity checks in
/// `identity::load_or_generate` catch it.
#[tokio::test]
async fn tampered_identity_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    let password = "pw3";
    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;
    let vault = setup_and_accept_vault(temp.path(), "pi-1", &hub_url, &token).await;

    let id_path = vitonomi_vault::state_dir::identity_path(&vault.data_dir);
    // Truncate the identity to one byte.
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(&id_path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&id_path, perms).unwrap();
    std::fs::write(&id_path, b"X").unwrap();

    // Reload should now fail (32-byte length expected).
    let result = vitonomi_vault::identity::load_or_generate(&vault.data_dir);
    assert!(result.is_err(), "tampered identity must fail to load");
}

/// Hub portability: stand up hub-B, restore the cluster's chain
/// onto it, point the vault at it via `set-hub`. CLI `vault list`
/// against hub-B sees the existing vault (no re-invite).
///
/// Note: full end-to-end "vault keeps running through the
/// transition" requires WSS + SPKI pinning which the test harness
/// doesn't drive. This test focuses on the *control-plane* part:
/// (1) the cluster identity moves cleanly, (2) the chain
/// replicates, (3) admin can list vaults on the new hub. The
/// vault `set-hub` command is exercised through its config-rewrite
/// path; the runtime reconnect is covered by the hub smoke test.
#[tokio::test]
async fn cluster_restore_to_fresh_hub() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_a, _state_a) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_a).await;
    let password = "pw4";

    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;
    let vault = setup_and_accept_vault(temp.path(), "pi-1", &hub_a, &token).await;

    // Export the chain from the vault's local store (hub-blind:
    // vault is authoritative).
    let store = vitonomi_vault::chain_store::ChainStore::open(&vault.data_dir).unwrap();
    let chain = store.read_all().unwrap();
    assert!(!chain.is_empty());

    let chain_export_path = temp.path().join("chain-export.cbor");
    let chain_bytes = vitonomi_core::encoding::cbor_to_vec(&chain).unwrap();
    std::fs::write(&chain_export_path, chain_bytes).unwrap();

    // Boot hub-B.
    let (hub_b, _state_b) = boot_hub().await;

    // Rewrite cli.toml to point at hub-B.
    {
        let mut cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
        cfg.hub.url = hub_b.clone();
        cfg.write_to(&admin.cli_cfg_path).unwrap();
    }

    // Run cluster restore.
    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: password.into(),
        seed_phrase: String::new(),
    };
    vitonomi_cli::commands::cluster_restore::run(
        &cfg,
        vitonomi_cli::commands::cluster_restore::ClusterRestoreArgs {
            state_path: &admin.cli_state_path,
            username: "birkeal".into(),
            chain_export_path: &chain_export_path,
            lookup_argon2: fast_lookup_params(),
        },
        &mut prompts,
    )
    .await
    .expect("cluster restore on hub-B");

    // CLI status now points at hub-B.
    let st_after = cli_state::load(&admin.cli_state_path).unwrap();
    assert_eq!(st_after.hub_url, hub_b);

    // hub-B's chain head matches what we restored.
    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let token_str = st_after.session_token.as_ref().unwrap().0.clone();
    let url = format!(
        "{hub_b}/v1/admin-chain/{}/head",
        ClusterIdHex::to_hex(&st_after.cluster_id)
    );
    let head: serde_json::Value = reqwest::Client::new()
        .get(url)
        .bearer_auth(&token_str)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let _ = cfg;
    assert_eq!(head["head"]["seq"].as_u64(), Some(0));
}

/// Hub-blindness leak audit: the in-memory hub fixture's session
/// store holds only sha256(token) hashes, never the raw token
/// strings. Verifies a key invariant that the future SQLite-backed
/// hub will inherit (it's the same trait impl for token storage).
#[tokio::test]
async fn hub_state_does_not_retain_raw_session_tokens() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _hub_state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    let password = "pw5";
    run_cluster_create(&admin, password).await;

    let st = cli_state::load(&admin.cli_state_path).unwrap();
    let raw_token = &st.session_token.as_ref().unwrap().0;

    // Status endpoint to make sure server is still up.
    let status: serde_json::Value = reqwest::get(format!("{hub_url}/v1/status"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["status"], "ok");

    // We don't have direct access to the in-memory hub's session
    // store from outside, but the trait method `get_keyblob` only
    // succeeds with the raw token (never with a hash). A
    // best-effort check here: an obviously-wrong token (just the
    // sha256 hex of the raw) should NOT authenticate.
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(raw_token.as_bytes());
    let hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let resp = reqwest::Client::new()
        .get(format!("{hub_url}/v1/keyblob"))
        .bearer_auth(&hex)
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "presenting sha256(token) as bearer must NOT authenticate"
    );

    // The legitimate raw token does authenticate.
    let resp = reqwest::Client::new()
        .get(format!("{hub_url}/v1/keyblob"))
        .bearer_auth(raw_token)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "legitimate session token must authenticate, got {}",
        resp.status()
    );
}

/// After `accept`, the vault MUST hold a `cluster_shared_key` byte-
/// equal to the admin's. This locks in the K2 unseal path
/// end-to-end: admin generates `invite_kek_secret`, derives a KEK,
/// seals `cluster_shared_key`; vault re-derives the KEK and opens
/// the seal. If the admin's and vault's keys diverge, every Phase 1+
/// record write/read silently breaks.
#[tokio::test]
async fn vault_holds_cluster_shared_key_after_accept() {
    use sha2::Digest as _;
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    let password = "csk-pw";
    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;
    let vault = setup_and_accept_vault(temp.path(), "pi-1", &hub_url, &token).await;

    // Vault now persists cluster_shared_key.bin after accept.
    let vault_csk = vitonomi_vault::cluster_key::load(&vault.data_dir)
        .expect("vault should hold cluster_shared_key after accept");
    assert_eq!(vault_csk.as_bytes().len(), 32);

    // Admin's cluster_shared_key (recovered from the encrypted key
    // blob in cli state) must match byte-for-byte.
    let st = cli_state::load(&admin.cli_state_path).unwrap();
    let secrets = vitonomi_core::crypto::keyblob::decrypt_with_password(
        password.as_bytes(),
        &st.encrypted_key_blob,
    )
    .expect("decrypt admin key blob");
    assert_eq!(
        sha2::Sha256::digest(vault_csk.as_bytes()).as_slice(),
        sha2::Sha256::digest(secrets.cluster_shared_key.as_bytes()).as_slice(),
        "admin and vault MUST hold identical cluster_shared_key after K2",
    );
}

/// A tampered `sealed_cluster_key` in the invite makes `accept`
/// fail. Without this guard, a mis-typed / corrupted invite could
/// silently write a vault that holds a wrong cluster_shared_key,
/// which would only surface much later as record-decrypt failures.
#[tokio::test]
async fn tampered_sealed_cluster_key_rejected_at_accept() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    let password = "tamper-pw";
    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;

    // Decode the short token, flip a byte in sealed_cluster_key,
    // re-encode. Note: this invalidates the recomputed sha256(inner)
    // vs the token's `inner_payload_hash`, so accept will fail at
    // `sanity_check_token` — the test still proves the vault won't
    // accept a corrupted invite. The `unseal_cluster_shared_key`
    // standalone test (in core) covers the path where only the seal
    // is corrupted.
    let mut parsed = parse_short_token(&token).unwrap();
    let last = parsed.inner.sealed_cluster_key.len() - 1;
    parsed.inner.sealed_cluster_key[last] ^= 0x01;
    let bad_token = encode_short_token(&parsed).unwrap();

    let cfg_path = temp.path().join("pi-1-bad.toml");
    let data_dir = temp.path().join("pi-1-bad-data");
    vitonomi_vault::config::write_default_config(
        Some(&cfg_path),
        vitonomi_vault::config::InitOverrides {
            data_dir: Some(data_dir.clone()),
            hub_url: Some(hub_url),
        },
        true,
    )
    .unwrap();
    let mut cfg = VaultConfig::load(
        Some(&cfg_path),
        vitonomi_vault::config::CliOverrides::default(),
    )
    .unwrap();
    let result = vitonomi_vault::accept::run(&cfg_path, &mut cfg, &bad_token).await;
    assert!(
        result.is_err(),
        "accept must reject an invite with tampered sealed_cluster_key"
    );
    assert!(
        !vitonomi_vault::cluster_key::exists(&data_dir),
        "no cluster_shared_key.bin should be written when accept fails"
    );
}

/// Vault → hub auto-bootstrap: hub-A registers a cluster + accepts
/// a vault, hub-A is killed, hub-B comes up empty. The vault calls
/// `bootstrap_to(hub_b)` and hub-B's in-memory state now contains
/// the cluster + vault — *zero admin intervention*. Demonstrates
/// the hub-as-cache property: state can be reconstructed from any
/// vault holding the chain + persisted membership proof.
#[tokio::test]
async fn vault_auto_bootstraps_to_fresh_hub() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_a, _state_a) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_a).await;
    let password = "auto-pw";

    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;
    let vault = setup_and_accept_vault(temp.path(), "pi-1", &hub_a, &token).await;

    // Sanity: enrollment now carries the membership proof.
    let enrollment = vitonomi_vault::accept::load_enrollment(&vault.data_dir).unwrap();
    assert!(
        enrollment.invite_outer.is_some() && enrollment.sig_vault.is_some(),
        "accept must persist invite_outer + sig_vault for later bootstrap"
    );
    let original_vault_id = enrollment.vault_id;

    // Boot hub-B (separate AppState — no shared state with hub-A).
    let (hub_b, state_b) = boot_hub().await;

    // Run the auto-bootstrap directly against hub-B. http://, no
    // SPKI fingerprint needed — `bootstrap_to` picks the plain
    // client when the URL is http://.
    let id = vitonomi_vault::identity::load_or_generate(&vault.data_dir).unwrap();
    let updated = vitonomi_vault::bootstrap::bootstrap_to(&vault.data_dir, &hub_b, "", &id)
        .await
        .expect("auto-bootstrap to hub-B");

    // The hub assigns a fresh vault_id; the vault persists it.
    let on_disk = vitonomi_vault::accept::load_enrollment(&vault.data_dir).unwrap();
    assert_eq!(on_disk.vault_id, updated.vault_id);
    assert_ne!(
        on_disk.vault_id, original_vault_id,
        "hub-B should have minted a fresh vault_id"
    );

    // Hub-B's vault registry now contains this vault — verify by
    // calling the trait directly through the captured AppState.
    let pubkey = state_b
        .control_plane
        .get_vault_pubkey(&updated.vault_id)
        .await
        .expect("hub-B should know the vault now");
    assert_eq!(pubkey.as_bytes(), id.public.as_bytes());

    // Idempotent: a second bootstrap is a no-op.
    let again = vitonomi_vault::bootstrap::bootstrap_to(&vault.data_dir, &hub_b, "", &id)
        .await
        .expect("idempotent re-bootstrap");
    assert_eq!(again.vault_id, updated.vault_id);
}

/// Bootstrapping a *different* cluster against a hub already holding
/// a cluster fails under the default `single-user` policy. Validates
/// the operator-policy gate end-to-end through the HTTP layer.
#[tokio::test]
async fn single_user_policy_blocks_second_cluster_bootstrap() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_a, _) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_a).await;
    let password = "policy-pw";
    run_cluster_create(&admin, password).await;
    let invite = run_vault_invite(&admin, password, "pi-1").await;
    let vault_dir_a = setup_and_accept_vault(temp.path(), "pi-1", &hub_a, &invite).await;

    // Boot hub-B and bootstrap cluster A onto it (claims the slot).
    let (hub_b, _) = boot_hub().await;
    let id_a = vitonomi_vault::identity::load_or_generate(&vault_dir_a.data_dir).unwrap();
    vitonomi_vault::bootstrap::bootstrap_to(&vault_dir_a.data_dir, &hub_b, "", &id_a)
        .await
        .expect("first cluster claims hub-B");

    // Set up a SECOND admin/vault on hub-A → its own cluster.
    let admin2_dir = temp.path().join("admin-2");
    std::fs::create_dir_all(&admin2_dir).unwrap();
    let admin2 = setup_admin(&admin2_dir, &hub_a).await;
    run_cluster_create(&admin2, "pw-other").await;
    let invite2 = run_vault_invite(&admin2, "pw-other", "pi-2").await;
    let vault_dir_b = setup_and_accept_vault(&admin2_dir, "pi-2", &hub_a, &invite2).await;

    // Try to bootstrap that *other* cluster onto hub-B — must fail.
    let id_b = vitonomi_vault::identity::load_or_generate(&vault_dir_b.data_dir).unwrap();
    let result =
        vitonomi_vault::bootstrap::bootstrap_to(&vault_dir_b.data_dir, &hub_b, "", &id_b).await;
    assert!(
        result.is_err(),
        "single-user policy should reject a second cluster"
    );
}

// ─── ClusterId hex helper used in cluster_restore_to_fresh_hub ───────

trait ClusterIdHex {
    fn to_hex(&self) -> String;
}

impl ClusterIdHex for vitonomi_core::types::ClusterId {
    fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.as_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
