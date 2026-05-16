//! E2E test for `vitonomi-cli mx register` against an in-memory hub.
//! Asserts admin registration succeeds and that the same call with a
//! stale session triggers the `relogin` password prompt. The mx
//! relay's `MxRelayId` is derived deterministically from the pubkey
//! on both sides, so nothing comes back over the wire.

use vitonomi_cli::commands::mx_register::{run as cli_mx_register, MxRegisterArgs};
use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;
use vitonomi_cli::state;

use vitonomi_core::crypto::pq::ml_dsa_65_keypair;
use vitonomi_core::encoding::hex_encode;

use vitonomi_integration::harness::{boot_hub, fast_lookup_params, run_cluster_create, setup_admin};

const PASSWORD: &str = "mx-register-e2e-pw";

#[tokio::test]
async fn happy_path_register_completes() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    run_cluster_create(&admin, PASSWORD).await;

    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let kp = ml_dsa_65_keypair().unwrap();
    let pubkey_hex = hex_encode(kp.public.as_bytes());

    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: PASSWORD.into(),
        seed_phrase: String::new(),
    };

    cli_mx_register(
        &cfg,
        MxRegisterArgs {
            state_path: &admin.cli_state_path,
            pubkey_hex,
            namespaces: vec!["vito.gg".to_string()],
            lookup_argon2: fast_lookup_params(),
        },
        &mut prompts,
    )
    .await
    .expect("register succeeds against in-memory hub");
}

#[tokio::test]
async fn relogins_when_session_token_missing() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    run_cluster_create(&admin, PASSWORD).await;

    // Drop the session token to force the relogin path.
    let mut st = state::load(&admin.cli_state_path).unwrap();
    st.session_token = None;
    st.session_expires_at_ms = 0;
    state::save(&admin.cli_state_path, &st).unwrap();

    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let kp = ml_dsa_65_keypair().unwrap();
    let pubkey_hex = hex_encode(kp.public.as_bytes());

    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: PASSWORD.into(),
        seed_phrase: String::new(),
    };

    cli_mx_register(
        &cfg,
        MxRegisterArgs {
            state_path: &admin.cli_state_path,
            pubkey_hex,
            namespaces: vec!["vito.gg".into(), "example.com".into()],
            lookup_argon2: fast_lookup_params(),
        },
        &mut prompts,
    )
    .await
    .expect("register succeeds even with stale session (relogin)");

    // Post-condition: session_token is now repopulated.
    let st_after = state::load(&admin.cli_state_path).unwrap();
    assert!(
        st_after.session_token.is_some(),
        "relogin should have written a fresh session_token"
    );
    assert!(st_after.session_expires_at_ms > 0);
}

#[tokio::test]
async fn rejects_malformed_pubkey_hex() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    run_cluster_create(&admin, PASSWORD).await;

    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: PASSWORD.into(),
        seed_phrase: String::new(),
    };

    let err = cli_mx_register(
        &cfg,
        MxRegisterArgs {
            state_path: &admin.cli_state_path,
            pubkey_hex: "not-hex-at-all".into(),
            namespaces: vec!["vito.gg".into()],
            lookup_argon2: fast_lookup_params(),
        },
        &mut prompts,
    )
    .await
    .expect_err("malformed hex should fail before any HTTP call");
    let msg = format!("{err:#}");
    assert!(msg.contains("--pubkey"), "expected pubkey error: {msg}");
}

#[tokio::test]
async fn rejects_empty_namespace_list() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    run_cluster_create(&admin, PASSWORD).await;

    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let kp = ml_dsa_65_keypair().unwrap();
    let pubkey_hex = hex_encode(kp.public.as_bytes());
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: PASSWORD.into(),
        seed_phrase: String::new(),
    };

    let err = cli_mx_register(
        &cfg,
        MxRegisterArgs {
            state_path: &admin.cli_state_path,
            pubkey_hex,
            namespaces: vec![],
            lookup_argon2: fast_lookup_params(),
        },
        &mut prompts,
    )
    .await
    .expect_err("empty namespace list should reject");
    assert!(format!("{err:#}").contains("namespace"));
}
