//! Vault-side bootstrap: write the vault config, optionally pin a
//! libp2p listen address, and run the `accept` flow against a
//! single-use invite token.

use std::path::{Path, PathBuf};

use vitonomi_vault::config::VaultConfig;

/// Where the vault was set up. Returned to callers that need the
/// `data_dir` to spawn the daemon or inspect on-disk state.
pub struct VaultContext {
    pub cfg_path: PathBuf,
    pub data_dir: PathBuf,
}

/// Optional knobs for `setup_and_accept_vault_with`.
#[derive(Default)]
pub struct VaultSetupOpts {
    /// Override the libp2p listen multiaddr persisted in the vault
    /// config. Daemon tests pin this to `/ip4/127.0.0.1/tcp/0` so
    /// the test process doesn't bind on `0.0.0.0`.
    pub listen_addr: Option<String>,
}

/// Default-options entrypoint — writes the vault config, accepts
/// the invite, and returns the resulting paths.
pub async fn setup_and_accept_vault(
    temp: &Path,
    name: &str,
    hub_url: &str,
    invite_token: &str,
) -> VaultContext {
    setup_and_accept_vault_with(temp, name, hub_url, invite_token, VaultSetupOpts::default()).await
}

/// Same as [`setup_and_accept_vault`] but accepts a [`VaultSetupOpts`]
/// to override the libp2p listen address (useful for daemon tests
/// that must bind to localhost only).
pub async fn setup_and_accept_vault_with(
    temp: &Path,
    name: &str,
    hub_url: &str,
    invite_token: &str,
    opts: VaultSetupOpts,
) -> VaultContext {
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

    if let Some(addr) = opts.listen_addr {
        let mut cfg = VaultConfig::load(
            Some(&cfg_path),
            vitonomi_vault::config::CliOverrides::default(),
        )
        .unwrap();
        cfg.p2p.listen_addr = addr;
        cfg.write_to(&cfg_path).unwrap();
    }

    let mut cfg = VaultConfig::load(
        Some(&cfg_path),
        vitonomi_vault::config::CliOverrides::default(),
    )
    .unwrap();
    vitonomi_vault::accept::run(&cfg_path, &mut cfg, invite_token)
        .await
        .expect("vault accept");
    VaultContext { cfg_path, data_dir }
}
