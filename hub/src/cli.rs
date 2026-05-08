//! clap-driven CLI. Subcommands `init` and `start`. Global
//! `--config <path>` (default `$XDG_CONFIG_HOME/vitonomi/hub.toml`).
//! Specific overrides (`--port`, `--data-dir`, `--single-user`)
//! beat values from the file via `figment`.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

use crate::config::HubConfig;

#[derive(Debug, Parser)]
#[command(name = "vitonomi-hub", version, about)]
pub struct Args {
    /// Path to the hub config TOML. Default:
    /// `$XDG_CONFIG_HOME/vitonomi/hub.toml`.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a default config file (interactively / via flags).
    Init {
        /// Bind address (default 127.0.0.1).
        #[arg(long)]
        bind_addr: Option<String>,
        /// Listen port (default 4443).
        #[arg(long)]
        port: Option<u16>,
        /// Data directory (DB, dev cert, etc.).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Lock the hub to a single cluster.
        #[arg(long)]
        single_user: bool,
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Start the server. Reads config (from `--config` or default
    /// XDG path) and binds the listener.
    Start {
        /// Override the configured port.
        #[arg(long)]
        port: Option<u16>,
        /// Override the configured bind address.
        #[arg(long)]
        bind_addr: Option<String>,
        /// Override the configured data dir.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Override the configured single-user flag.
        #[arg(long)]
        single_user: bool,
    },
    /// Print the hub's TLS leaf cert SPKI fingerprint to stdout.
    /// Generates the dev cert if one isn't yet present (matching
    /// what `start` would do). Use this value as the `--fingerprint`
    /// argument to `vitonomi-cli vault invite`.
    Fingerprint {
        /// Override the configured data dir (where dev cert lives).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

/// Entrypoint called by `main.rs`.
///
/// # Errors
///
/// Surfaces config-load failures, listener-bind failures, and
/// server-startup failures.
pub async fn run_cli() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Init {
            bind_addr,
            port,
            data_dir,
            single_user,
            force,
        } => crate::config::write_default_config(
            args.config.as_deref(),
            crate::config::InitOverrides {
                bind_addr,
                port,
                data_dir,
                single_user,
            },
            force,
        )
        .context("write default config"),
        Command::Start {
            port,
            bind_addr,
            data_dir,
            single_user,
        } => {
            crate::config::init_logging();
            let cfg = HubConfig::load(
                args.config.as_deref(),
                crate::config::CliOverrides {
                    port,
                    bind_addr,
                    data_dir,
                    single_user: single_user.then_some(true),
                },
            )?;
            tracing::info!(
                bind_addr = %cfg.server.bind_addr,
                port = cfg.server.port,
                single_user = cfg.server.single_user,
                data_dir = %cfg.paths.data_dir.display(),
                "vitonomi-hub starting",
            );
            crate::server::run(cfg).await
        }
        Command::Fingerprint { data_dir } => {
            let cfg = HubConfig::load(
                args.config.as_deref(),
                crate::config::CliOverrides {
                    data_dir,
                    ..Default::default()
                },
            )?;
            let tls = crate::tls::resolve(&cfg).context("resolve TLS material")?;
            println!("{}", tls.spki_fingerprint);
            Ok(())
        }
    }
}
