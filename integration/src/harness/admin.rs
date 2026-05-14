//! Admin-side bootstrap: write a CLI config + state, run
//! `cluster create` and `vault invite` via the CLI library
//! entrypoints (no subprocess), inject the password through
//! `ScriptedPrompts`.

use std::path::{Path, PathBuf};

use vitonomi_cli::commands::cluster_create::{run as cli_cluster_create, ClusterCreateArgs};
use vitonomi_cli::commands::vault_invite::{run as cli_vault_invite, VaultInviteArgs};
use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;

use super::params::{dummy_fingerprint, fast_keyblob_params, fast_lookup_params};

/// Bundle of admin-side paths the harness produces.
pub struct AdminContext {
    pub cli_cfg_path: PathBuf,
    pub cli_state_path: PathBuf,
    pub hub_url: String,
}

/// Write a default `cli.toml` pointing at `hub_url` and place the
/// state file inside `temp/cli-state/`.
pub async fn setup_admin(temp: &Path, hub_url: &str) -> AdminContext {
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
        hub_url: hub_url.into(),
    }
}

/// Run `vitonomi-cli cluster create` with username `birkeal` and the
/// supplied password. Uses the cheap Argon2id profile.
pub async fn run_cluster_create(admin: &AdminContext, password: &str) {
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

/// Run `vitonomi-cli vault invite` and return the short-token string.
pub async fn run_vault_invite(admin: &AdminContext, password: &str, vault_name: &str) -> String {
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
