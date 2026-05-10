//! clap dispatcher for `vitonomi-cli`.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands;
use crate::config::CliConfig;
use crate::prompts::InteractivePrompts;
use crate::state;

#[derive(Debug, Parser)]
#[command(name = "vitonomi-cli", version, about)]
pub struct Args {
    /// Path to `cli.toml`. Default: `$XDG_CONFIG_HOME/vitonomi/cli.toml`.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a default `cli.toml`.
    Init {
        #[arg(long)]
        hub: Option<String>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Bootstrap a fresh cluster on the configured hub.
    Cluster(ClusterCmd),
    /// Run Scheme A login.
    Login,
    /// Revoke session + delete local state.
    Logout,
    /// Print current session, cluster, hub.
    Status,
    /// Vault directory + invite operations.
    Vault(VaultCmd),
}

#[derive(Debug, clap::Args)]
pub struct ClusterCmd {
    #[command(subcommand)]
    pub action: ClusterAction,
}

#[derive(Debug, Subcommand)]
pub enum ClusterAction {
    Create {
        #[arg(long)]
        username: String,
    },
    Restore {
        #[arg(long)]
        username: String,
        #[arg(long)]
        chain_file: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
pub struct VaultCmd {
    #[command(subcommand)]
    pub action: VaultAction,
}

#[derive(Debug, Subcommand)]
pub enum VaultAction {
    Invite {
        #[arg(long)]
        name: String,
        /// Hub TLS cert SPKI fingerprint (`sha256:<base64url>`).
        /// Optional: defaults to `cli.toml`'s persisted
        /// `hub.cert_fingerprint` (auto-pinned by `cluster create`).
        /// Pass explicitly to override after a hub cert rotation.
        #[arg(long)]
        fingerprint: Option<String>,
        /// Invite TTL in seconds. Default: 900 (15 minutes).
        #[arg(long, default_value_t = 900)]
        ttl: u64,
    },
    List,
}

/// Bin entrypoint. Parses argv from caller (so tests can drive
/// without mutating `std::env::args`).
///
/// # Errors
///
/// Surfaces config / network / persistence errors.
pub async fn run_cli<I, T>(argv: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = Args::parse_from(argv);
    crate::config::init_logging();
    let config_path = match args.config {
        Some(ref p) => p.clone(),
        None => crate::config::default_config_path()?,
    };
    match args.command {
        Command::Init {
            hub,
            state_dir,
            force,
        } => commands::init::run(Some(&config_path), hub, state_dir, force),
        Command::Cluster(c) => match c.action {
            ClusterAction::Create { username } => {
                let cfg = CliConfig::load(Some(&config_path))?;
                let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
                let mut prompts = InteractivePrompts;
                commands::cluster_create::run(
                    &cfg,
                    commands::cluster_create::ClusterCreateArgs {
                        config_path: &config_path,
                        state_path: &state_path,
                        username,
                        keyblob_argon2:
                            vitonomi_core::crypto::argon2::Argon2Params::default_for_env(),
                        lookup_argon2:
                            vitonomi_core::crypto::lookup_id::LookupIdParams::default_for_env(),
                        print_seed_phrase: true,
                    },
                    &mut prompts,
                )
                .await
            }
            ClusterAction::Restore {
                username,
                chain_file,
            } => {
                let cfg = CliConfig::load(Some(&config_path))?;
                let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
                let mut prompts = InteractivePrompts;
                commands::cluster_restore::run(
                    &cfg,
                    commands::cluster_restore::ClusterRestoreArgs {
                        state_path: &state_path,
                        username,
                        chain_export_path: &chain_file,
                        lookup_argon2:
                            vitonomi_core::crypto::lookup_id::LookupIdParams::default_for_env(),
                    },
                    &mut prompts,
                )
                .await
            }
        },
        Command::Login => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            let mut prompts = InteractivePrompts;
            commands::login::run(
                &cfg,
                commands::login::LoginArgs {
                    state_path: &state_path,
                    lookup_argon2:
                        vitonomi_core::crypto::lookup_id::LookupIdParams::default_for_env(),
                },
                &mut prompts,
            )
            .await
        }
        Command::Logout => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            commands::logout::run(&cfg, &state_path).await
        }
        Command::Status => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            commands::status::run(&cfg, &state_path)
        }
        Command::Vault(v) => match v.action {
            VaultAction::Invite {
                name,
                fingerprint,
                ttl,
            } => {
                let cfg = CliConfig::load(Some(&config_path))?;
                let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
                let resolved_fp = match fingerprint {
                    Some(fp) => fp,
                    None if !cfg.hub.cert_fingerprint.is_empty() => {
                        cfg.hub.cert_fingerprint.clone()
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "no hub.cert_fingerprint in cli.toml — \
                             re-run `cluster create` against the live hub, \
                             or pass `--fingerprint sha256:...` explicitly"
                        ));
                    }
                };
                let mut prompts = InteractivePrompts;
                commands::vault_invite::run(
                    &cfg,
                    commands::vault_invite::VaultInviteArgs {
                        state_path: &state_path,
                        vault_name: name,
                        hub_cert_fingerprint: resolved_fp,
                        ttl_secs: ttl,
                    },
                    &mut prompts,
                )
                .await
                .map(|_| ())
            }
            VaultAction::List => {
                let cfg = CliConfig::load(Some(&config_path))?;
                let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
                commands::vault_list::run(&cfg, &state_path).await
            }
        },
    }
}

fn state_dir_from_cfg(cfg: &CliConfig) -> Option<PathBuf> {
    if cfg.paths.state_dir.is_empty() {
        None
    } else {
        Some(PathBuf::from(&cfg.paths.state_dir))
    }
}
