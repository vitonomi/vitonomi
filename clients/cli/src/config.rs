//! `cli.toml` — minimal config for the admin CLI. Holds the hub
//! URL only; per-cluster sensitive material (pepper, admin pubkey,
//! session token) lives in the separate `state.json` (mode 0600).

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CliConfig {
    #[serde(default)]
    pub hub: HubConfig,
    #[serde(default)]
    pub paths: PathsConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HubConfig {
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    #[serde(default)]
    pub state_dir: String,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            state_dir: String::new(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct InitOverrides {
    pub hub_url: Option<String>,
    pub state_dir: Option<PathBuf>,
}

impl CliConfig {
    /// Load with full layering. Falls back to defaults if no
    /// config file exists yet.
    ///
    /// # Errors
    ///
    /// Returns `anyhow::Error` on TOML parse / env failures.
    pub fn load(config_path: Option<&Path>) -> anyhow::Result<Self> {
        let path = match config_path {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };
        let mut fig = Figment::new().merge(Serialized::defaults(CliConfig::default()));
        if path.exists() {
            fig = fig.merge(Toml::file(&path));
        }
        fig = fig.merge(Env::prefixed("VITONOMI_CLI_").split("__"));
        fig.extract().context("invalid cli config")
    }

    /// Persist this config as TOML (mode 0644 — config holds no
    /// secrets).
    ///
    /// # Errors
    ///
    /// File-system / serialisation failures.
    pub fn write_to(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create config dir {}", parent.display()))?;
        }
        let toml = toml::to_string_pretty(self).context("serialize cli config")?;
        std::fs::write(path, toml).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}

/// `$XDG_CONFIG_HOME/vitonomi/cli.toml`.
///
/// # Errors
///
/// `anyhow::Error` if no config home can be resolved.
pub fn default_config_path() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "vitonomi", "vitonomi")
        .ok_or_else(|| anyhow!("cannot resolve $XDG_CONFIG_HOME for vitonomi"))?;
    Ok(dirs.config_dir().join("cli.toml"))
}

/// Initialise tracing for the CLI.
pub fn init_logging() {
    let filter = EnvFilter::try_from_env("VITONOMI_LOG")
        .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
        .unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().compact().with_writer(std::io::stderr))
        .try_init();
}

/// Write a default config (interactively or via flags).
///
/// # Errors
///
/// File-system errors or refusal to overwrite.
pub fn write_default_config(
    config_path: Option<&Path>,
    overrides: InitOverrides,
    force: bool,
) -> anyhow::Result<()> {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => default_config_path()?,
    };
    if path.exists() && !force {
        bail!(
            "{} already exists; use --force to overwrite",
            path.display()
        );
    }
    let mut cfg = CliConfig::default();
    if let Some(u) = overrides.hub_url {
        cfg.hub.url = u;
    }
    if let Some(d) = overrides.state_dir {
        cfg.paths.state_dir = d.display().to_string();
    }
    cfg.write_to(&path)?;
    eprintln!("wrote default config: {}", path.display());
    Ok(())
}
