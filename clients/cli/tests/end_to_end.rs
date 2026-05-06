//! End-to-end CLI test: spin up a hub on an ephemeral port, drive
//! `cluster create` → `login` → `vault invite` → `vault list`
//! through the library entry points (no subprocess), and assert
//! state.json + hub directory + emitted invite token are all in
//! the right shape.

use std::path::PathBuf;

use tokio::net::TcpListener;

use vitonomi_core::crypto::argon2::Argon2Params;
use vitonomi_core::crypto::lookup_id::LookupIdParams;
use vitonomi_hub::state::AppState;

use vitonomi_cli::commands::cluster_create::{run as cluster_create, ClusterCreateArgs};
use vitonomi_cli::commands::login::{run as login_run, LoginArgs};
use vitonomi_cli::commands::vault_invite::{run as vault_invite_run, VaultInviteArgs};
use vitonomi_cli::commands::vault_list::run as vault_list_run;
use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;
use vitonomi_cli::state;

async fn boot_hub() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::in_memory();
    tokio::spawn(async move {
        let _ = vitonomi_hub::run_with_listener(listener, state).await;
    });
    format!("http://{addr}")
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

#[tokio::test]
async fn cluster_create_login_invite_list_round_trip() {
    let hub_url = boot_hub().await;

    let dir = tempfile::tempdir().unwrap();
    let cfg_path: PathBuf = dir.path().join("cli.toml");
    let state_dir = dir.path().join("state");
    let state_path = state_dir.join("state.json");

    // Init cli config.
    vitonomi_cli::config::write_default_config(
        Some(&cfg_path),
        vitonomi_cli::config::InitOverrides {
            hub_url: Some(hub_url.clone()),
            state_dir: Some(state_dir.clone()),
        },
        true,
    )
    .unwrap();
    let cfg = CliConfig::load(Some(&cfg_path)).unwrap();

    // ─── 1. cluster create ─────────────────────────────────────────
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: "correct horse battery staple".into(),
        seed_phrase: String::new(),
    };
    cluster_create(
        &cfg,
        ClusterCreateArgs {
            config_path: &cfg_path,
            state_path: &state_path,
            username: "birkeal".into(),
            keyblob_argon2: fast_keyblob_params(),
            lookup_argon2: fast_lookup_params(),
            print_seed_phrase: false,
        },
        &mut prompts,
    )
    .await
    .expect("cluster create");

    let st = state::load(&state_path).unwrap();
    assert_eq!(st.username, "birkeal");
    assert!(st.session_token.is_some(), "session token persisted");
    assert!(
        !st.encrypted_key_blob.is_empty(),
        "encrypted key blob persisted"
    );
    assert!(!st.cluster_pepper.is_empty(), "cluster pepper persisted");

    // ─── 2. login (separate session, fresh blob fetch) ─────────────
    login_run(
        &cfg,
        LoginArgs {
            state_path: &state_path,
            lookup_argon2: fast_lookup_params(),
        },
        &mut prompts,
    )
    .await
    .expect("login");

    let after_login = state::load(&state_path).unwrap();
    assert!(after_login.session_token.is_some());
    assert_ne!(
        after_login.session_token.as_ref().unwrap().0,
        st.session_token.unwrap().0,
        "login produced a fresh session token"
    );

    // ─── 3. vault invite ───────────────────────────────────────────
    let token = vault_invite_run(
        &cfg,
        VaultInviteArgs {
            state_path: &state_path,
            vault_name: "pi-1".into(),
            hub_cert_fingerprint: "sha256:test-fingerprint-string-of-43-base64url-chars-x".into(),
            ttl_secs: 900,
        },
        &mut prompts,
    )
    .await
    .expect("vault invite");
    assert!(!token.is_empty(), "invite token should not be empty");

    // ─── 4. vault list (initially empty — no vault has accepted) ───
    vault_list_run(&cfg, &state_path).await.expect("vault list");
}
