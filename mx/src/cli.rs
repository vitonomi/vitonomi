//! clap-driven CLI for `vitonomi-mx`.
//!
//! Slice 0 wires `init` (write default `mx.toml`), `start`
//! (currently a stub returning "not implemented"), and `status`
//! (print the loaded config). Slice 7 fills `start` with the SMTP
//! receiver + signed hub-push pipeline.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "vitonomi-mx", version, about)]
pub struct Args {
    /// Path to the mx config TOML. Default:
    /// `$XDG_CONFIG_HOME/vitonomi/mx.toml`.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a default config file (interactively / via flags).
    Init {
        /// SMTP bind address (default 127.0.0.1; production is
        /// usually `0.0.0.0`).
        #[arg(long)]
        bind_addr: Option<String>,
        /// SMTP listen port (default 25).
        #[arg(long)]
        port: Option<u16>,
        /// Base domain the relay is authoritative for
        /// (e.g. `vito.gg`).
        #[arg(long)]
        base: Option<String>,
        /// Hub URL the relay pushes inbound ciphertext to.
        #[arg(long)]
        hub: Option<String>,
        /// Persistent data dir (relay identity, dev cert, …).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Start the SMTP receiver. Slice 0 stub: returns an error.
    /// Slice 7 wires the real pipeline.
    Start {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        bind_addr: Option<String>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Print the loaded config to stdout (yaml-ish, one line per
    /// field). Useful for verifying CLI-overrides + env
    /// merging without booting the SMTP listener.
    Status {
        #[arg(long)]
        bind_addr: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

/// Entrypoint called by `main.rs`.
///
/// # Errors
///
/// Surfaces config-load failures and (in slice 0) the not-yet-
/// implemented `start` command.
pub async fn run_cli() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Init {
            bind_addr,
            port,
            base,
            hub,
            data_dir,
            force,
        } => crate::config::write_default_config(
            args.config.as_deref(),
            crate::config::InitOverrides {
                bind_addr,
                port,
                data_dir,
                base_domain: base,
                hub_url: hub,
            },
            force,
        )
        .context("write default config"),
        Command::Start {
            port,
            bind_addr,
            data_dir,
        } => {
            crate::config::init_logging();
            let cfg = crate::config::MxConfig::load(
                args.config.as_deref(),
                crate::config::CliOverrides {
                    bind_addr,
                    port,
                    data_dir,
                    ..Default::default()
                },
            )?;
            crate::commands::start::run(cfg).await
        }
        Command::Status {
            bind_addr,
            port,
            data_dir,
        } => {
            let cfg = crate::config::MxConfig::load(
                args.config.as_deref(),
                crate::config::CliOverrides {
                    bind_addr,
                    port,
                    data_dir,
                    ..Default::default()
                },
            )?;
            crate::commands::status::run(&cfg)
        }
    }
}
