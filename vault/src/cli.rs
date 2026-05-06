//! clap-driven CLI dispatcher. Subcommands mirror the plan:
//! `init`, `accept`, `start`, `set-hub`, `status`, `info`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::{CliOverrides, VaultConfig};

#[derive(Debug, Parser)]
#[command(name = "vitonomi-vault", version, about)]
pub struct Args {
    /// Path to the vault config TOML. Default:
    /// `$XDG_CONFIG_HOME/vitonomi/vault.toml`.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a default config file.
    Init {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Hub URL the vault should dial (e.g. `https://hub.example:4443`).
        #[arg(long)]
        hub: Option<String>,
        #[arg(long)]
        force: bool,
    },
    /// Accept an admin-issued invite token. Persists hub
    /// `cert_fingerprint` in `vault.toml`, registers with the hub,
    /// stores the genesis chain head locally.
    Accept {
        #[arg(long)]
        invite: String,
    },
    /// Open a long-lived authenticated WebSocket session to the hub.
    Start {},
    /// Re-point this vault at a new hub. Validates the new hub
    /// serves a chain head consistent with our cached cluster admin
    /// pubkey before rewriting `vault.toml`.
    SetHub {
        #[arg(long)]
        url: String,
        #[arg(long)]
        fingerprint: String,
    },
    /// Print enrollment + chain summary.
    Status {},
    /// Print key paths + identity pubkey.
    Info {},
}

/// Bin entrypoint.
///
/// # Errors
///
/// Surfaces config / network / persistence errors.
pub async fn run_cli() -> anyhow::Result<()> {
    let args = Args::parse();
    crate::config::init_logging();
    let config_path = match args.config {
        Some(ref p) => p.clone(),
        None => crate::config::default_config_path()?,
    };
    match args.command {
        Command::Init {
            data_dir,
            hub,
            force,
        } => crate::commands::init::run(Some(&config_path), data_dir, hub, force),
        Command::Accept { invite } => {
            let cfg = VaultConfig::load(Some(&config_path), CliOverrides::default())?;
            crate::commands::accept::run(&config_path, cfg, &invite).await
        }
        Command::Start {} => {
            let cfg = VaultConfig::load(Some(&config_path), CliOverrides::default())?;
            crate::commands::start::run(cfg).await
        }
        Command::SetHub { url, fingerprint } => {
            let cfg = VaultConfig::load(Some(&config_path), CliOverrides::default())?;
            crate::commands::set_hub::run(&config_path, cfg, &url, &fingerprint).await
        }
        Command::Status {} => {
            let cfg = VaultConfig::load(Some(&config_path), CliOverrides::default())?;
            crate::commands::status::run(cfg)
        }
        Command::Info {} => {
            let cfg = VaultConfig::load(Some(&config_path), CliOverrides::default())?;
            crate::commands::info::run(cfg)
        }
    }
}
