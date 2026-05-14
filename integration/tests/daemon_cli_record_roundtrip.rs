//! Real-binary end-to-end test.
//!
//! 1. Boot the in-memory hub on an ephemeral HTTP port.
//! 2. Run the CLI's `cluster_create` + `vault_invite` flows via the
//!    library entrypoints (`ScriptedPrompts` injects the password).
//! 3. Accept the invite from the vault side.
//! 4. Spawn `vitonomi_vault::commands::start::run` as a background
//!    task — this is the full daemon: opens SqliteVaultStorage, spawns
//!    the libp2p Swarm, connects WSS to the hub, fires
//!    `AdvertiseAddrsFrame` on the heartbeat.
//! 5. Wait for the hub's vault directory to include a non-empty
//!    multiaddr (proves the daemon's libp2p Swarm is bound and the
//!    advertise round-tripped).
//! 6. Run `record put` then `record get` via the CLI command modules,
//!    talking to the running daemon over real libp2p.
//! 7. Assert the recovered plaintext matches the uploaded file.

use std::path::Path;
use std::time::Duration;

use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;

use vitonomi_vault::config::VaultConfig;

use vitonomi_integration::harness::{
    boot_hub, run_cluster_create, run_vault_invite, setup_admin, setup_and_accept_vault_with,
    VaultSetupOpts,
};

// ─── helpers ─────────────────────────────────────────────────

async fn wait_for_vault_multiaddrs(
    hub_url: &str,
    state_path: &Path,
    timeout: Duration,
) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let bearer = {
        let st = vitonomi_cli::state::load(state_path).unwrap();
        st.session_token
            .as_ref()
            .map(|t| t.0.clone())
            .expect("session token after cluster_create")
    };
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "vault never advertised a libp2p multiaddr within {:?}",
                timeout
            );
        }
        let resp = client
            .get(format!("{}/v1/vaults", hub_url.trim_end_matches('/')))
            .bearer_auth(&bearer)
            .send()
            .await;
        if let Ok(r) = resp {
            if r.status().is_success() {
                let body: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
                if let Some(vaults) = body.get("vaults").and_then(|v| v.as_array()) {
                    for v in vaults {
                        if let Some(m) = v.get("multiaddrs").and_then(|m| m.as_array()) {
                            let addrs: Vec<String> = m
                                .iter()
                                .filter_map(|s| s.as_str().map(String::from))
                                .collect();
                            if !addrs.is_empty() {
                                return addrs;
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ─── test ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_put_get_roundtrip_via_running_daemon() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, hub_state) = boot_hub().await;

    let admin = setup_admin(temp.path(), &hub_url).await;
    let password = "correct horse battery staple";

    run_cluster_create(&admin, password).await;
    let token = run_vault_invite(&admin, password, "pi-1").await;

    let vault = setup_and_accept_vault_with(
        temp.path(),
        "pi-1",
        &hub_url,
        &token,
        VaultSetupOpts {
            listen_addr: Some("/ip4/127.0.0.1/tcp/0".into()),
        },
    )
    .await;

    // Spawn the full vault daemon.
    let vault_cfg = VaultConfig::load(
        Some(&vault.cfg_path),
        vitonomi_vault::config::CliOverrides::default(),
    )
    .unwrap();
    let vault_task = tokio::spawn(async move {
        let r = vitonomi_vault::commands::start::run(vault_cfg).await;
        if let Err(e) = &r {
            eprintln!("vault daemon exited with error: {e:#}");
        }
        r
    });

    // Wait for the daemon's libp2p Swarm to advertise its multiaddr.
    let _ = hub_state; // capture-suppress
    let _addrs =
        wait_for_vault_multiaddrs(&hub_url, &admin.cli_state_path, Duration::from_secs(15)).await;

    // ── CLI: record put (metadata + body) ───────────────────────
    let metadata_path = temp.path().join("metadata.cbor");
    let body_path = temp.path().join("body.bin");
    let metadata_bytes = b"title=netflix";
    let body_bytes = br#"{"password":"hunter2","totp":null}"#;
    std::fs::write(&metadata_path, metadata_bytes).unwrap();
    std::fs::write(&body_path, body_bytes).unwrap();

    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: password.into(),
        seed_phrase: String::new(),
    };

    use vitonomi_cli::commands::record_get::RecordFace;
    use vitonomi_cli::commands::{record_get, record_put};
    use vitonomi_core::record::RecordType;

    record_put::run(
        &cfg,
        record_put::RecordPutArgs {
            state_path: &admin.cli_state_path,
            record_type: RecordType::Credential,
            metadata_file: metadata_path.clone(),
            body_file: Some(body_path.clone()),
        },
        &mut prompts,
    )
    .await
    .expect("record put");

    // Find the record id via list_metadata.
    let id_hex = {
        use vitonomi_cli::commands::record_session;
        let session = record_session::open(&cfg, &admin.cli_state_path, &mut prompts)
            .await
            .expect("session for list");
        let listed = session
            .record_store
            .list_metadata(RecordType::Credential)
            .await
            .expect("list_metadata");
        let id_hex = listed
            .first()
            .map(|(id, _)| id.to_hex())
            .expect("at least one record after put");
        session.shutdown().await;
        id_hex
    };

    // GET metadata face — recover and compare.
    let recovered_meta_path = temp.path().join("recovered-meta.bin");
    record_get::run(
        &cfg,
        record_get::RecordGetArgs {
            state_path: &admin.cli_state_path,
            record_type: RecordType::Credential,
            id_hex: id_hex.clone(),
            face: RecordFace::Metadata,
            out: Some(recovered_meta_path.clone()),
        },
        &mut prompts,
    )
    .await
    .expect("record get metadata");
    let recovered_meta = std::fs::read(&recovered_meta_path).expect("read recovered metadata");
    assert_eq!(
        recovered_meta, metadata_bytes,
        "recovered metadata must match uploaded bytes"
    );

    // GET body face — recover and compare.
    let recovered_body_path = temp.path().join("recovered-body.bin");
    record_get::run(
        &cfg,
        record_get::RecordGetArgs {
            state_path: &admin.cli_state_path,
            record_type: RecordType::Credential,
            id_hex: id_hex.clone(),
            face: RecordFace::Body,
            out: Some(recovered_body_path.clone()),
        },
        &mut prompts,
    )
    .await
    .expect("record get body");
    let recovered_body = std::fs::read(&recovered_body_path).expect("read recovered body");
    assert_eq!(
        recovered_body, body_bytes,
        "recovered body must match uploaded bytes"
    );

    // Cleanup — abort the daemon task.
    vault_task.abort();
    let _ = vault_task.await;
}
