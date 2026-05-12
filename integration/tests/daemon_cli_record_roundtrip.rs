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

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::TcpListener;

use vitonomi_cli::commands::cluster_create::{run as cli_cluster_create, ClusterCreateArgs};
use vitonomi_cli::commands::vault_invite::{run as cli_vault_invite, VaultInviteArgs};
use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;

use vitonomi_core::crypto::argon2::Argon2Params;
use vitonomi_core::crypto::lookup_id::LookupIdParams;

use vitonomi_hub::state::AppState;
use vitonomi_vault::config::VaultConfig;

// ─── helpers ─────────────────────────────────────────────────

async fn boot_hub() -> (String, AppState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::in_memory();
    let state_clone = state.clone();
    tokio::spawn(async move {
        let _ = vitonomi_hub::run_with_listener(listener, state_clone).await;
    });
    (format!("http://{addr}"), state)
}

fn fast_keyblob_params() -> Argon2Params {
    Argon2Params {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
        out_len: 32,
    }
}

fn fast_lookup_params() -> LookupIdParams {
    LookupIdParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

fn dummy_fingerprint() -> String {
    // 32 zero bytes → 43-char URL-safe base64url, no padding. The
    // bytes never need to match a real cert: the hub is http:// in
    // tests, so the SPKI verifier is constructed but never invoked.
    "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()
}

struct AdminContext {
    cli_cfg_path: PathBuf,
    cli_state_path: PathBuf,
}

async fn setup_admin(temp: &Path, hub_url: &str) -> AdminContext {
    let cfg_path = temp.join("cli.toml");
    let state_dir = temp.join("cli-state");
    let state_path = state_dir.join("state.json");
    vitonomi_cli::config::write_default_config(
        Some(&cfg_path),
        vitonomi_cli::config::InitOverrides {
            hub_url: Some(hub_url.to_string()),
            state_dir: Some(state_dir),
        },
        true,
    )
    .unwrap();
    AdminContext {
        cli_cfg_path: cfg_path,
        cli_state_path: state_path,
    }
}

async fn run_cluster_create(admin: &AdminContext, password: &str) {
    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: password.into(),
        seed_phrase: String::new(),
    };
    cli_cluster_create(
        &cfg,
        ClusterCreateArgs {
            config_path: &admin.cli_cfg_path,
            state_path: &admin.cli_state_path,
            username: "birkeal".into(),
            keyblob_argon2: fast_keyblob_params(),
            lookup_argon2: fast_lookup_params(),
            print_seed_phrase: false,
        },
        &mut prompts,
    )
    .await
    .expect("cluster create");
}

async fn run_vault_invite(admin: &AdminContext, password: &str, vault_name: &str) -> String {
    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: password.into(),
        seed_phrase: String::new(),
    };
    cli_vault_invite(
        &cfg,
        VaultInviteArgs {
            state_path: &admin.cli_state_path,
            vault_name: vault_name.into(),
            hub_cert_fingerprint: dummy_fingerprint(),
            ttl_secs: 900,
        },
        &mut prompts,
    )
    .await
    .expect("vault invite")
}

async fn setup_and_accept_vault(
    temp: &Path,
    name: &str,
    hub_url: &str,
    invite_token: &str,
) -> PathBuf {
    let cfg_path = temp.join(format!("{name}.toml"));
    let data_dir = temp.join(format!("{name}-data"));
    vitonomi_vault::config::write_default_config(
        Some(&cfg_path),
        vitonomi_vault::config::InitOverrides {
            data_dir: Some(data_dir.clone()),
            hub_url: Some(hub_url.into()),
        },
        true,
    )
    .unwrap();
    // Force the daemon to bind to localhost so this test doesn't try
    // to listen on 0.0.0.0.
    let mut cfg = VaultConfig::load(
        Some(&cfg_path),
        vitonomi_vault::config::CliOverrides::default(),
    )
    .unwrap();
    cfg.p2p.listen_addr = "/ip4/127.0.0.1/tcp/0".into();
    cfg.write_to(&cfg_path).unwrap();

    let mut cfg = VaultConfig::load(
        Some(&cfg_path),
        vitonomi_vault::config::CliOverrides::default(),
    )
    .unwrap();
    vitonomi_vault::accept::run(&cfg_path, &mut cfg, invite_token)
        .await
        .expect("vault accept");
    cfg_path
}

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

    let vault_cfg_path = setup_and_accept_vault(temp.path(), "pi-1", &hub_url, &token).await;

    // Spawn the full vault daemon.
    let vault_cfg = VaultConfig::load(
        Some(&vault_cfg_path),
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

    // ── CLI: record put ─────────────────────────────────────────
    let payload_path = temp.path().join("credential.json");
    let payload = br#"{"site":"netflix.com","user":"birkeal","password":"hunter2"}"#;
    std::fs::write(&payload_path, payload).unwrap();

    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: password.into(),
        seed_phrase: String::new(),
    };

    // Capture stdout for the put command via a fork — instead, call
    // the record_store directly and grab the id. We use the same
    // command module that the clap dispatcher calls.
    use vitonomi_cli::commands::{record_get, record_put};
    use vitonomi_core::record::RecordType;

    // PUT — emits the record id to stdout; for the test we use a
    // fresh round-trip helper that returns the id directly via the
    // session helper.
    {
        // Run the put through the public command function (output
        // goes to stdout, which we don't intercept here). Then list
        // to recover the id.
        record_put::run(
            &cfg,
            record_put::RecordPutArgs {
                state_path: &admin.cli_state_path,
                record_type: RecordType::Credential,
                file: payload_path.clone(),
            },
            &mut prompts,
        )
        .await
        .expect("record put");
    }

    // Find the record id via list.
    let id_hex = {
        use vitonomi_cli::commands::record_session;
        let session = record_session::open(&cfg, &admin.cli_state_path, &mut prompts)
            .await
            .expect("session for list");
        let listed = session
            .record_store
            .list(RecordType::Credential)
            .await
            .expect("list records");
        let id_hex = listed
            .first()
            .map(|(id, _)| id.to_hex())
            .expect("at least one record after put");
        session.shutdown().await;
        id_hex
    };

    // GET — recover into a separate file and compare.
    let recovered_path = temp.path().join("recovered.json");
    record_get::run(
        &cfg,
        record_get::RecordGetArgs {
            state_path: &admin.cli_state_path,
            record_type: RecordType::Credential,
            id_hex: id_hex.clone(),
            out: Some(recovered_path.clone()),
        },
        &mut prompts,
    )
    .await
    .expect("record get");

    let recovered = std::fs::read(&recovered_path).expect("read recovered file");
    assert_eq!(
        recovered, payload,
        "recovered plaintext must match uploaded bytes"
    );

    // Cleanup — abort the daemon task.
    vault_task.abort();
    let _ = vault_task.await;
}
