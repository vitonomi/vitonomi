//! Layered config: defaults → `vault.toml` → env (`VITONOMI_VAULT_*`)
//! → CLI overrides. Loaded by `VaultConfig::load`. Subcommands like
//! `accept` and `set-hub` rewrite specific fields in place via
//! [`VaultConfig::write_to`].

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultConfig {
    pub paths: PathsConfig,
    #[serde(default)]
    pub hub: HubConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    pub data_dir: PathBuf,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/vitonomi-vault"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HubConfig {
    /// Set by `init` (or `set-hub`); read by `accept` / `start`.
    #[serde(default)]
    pub url: String,
    /// `sha256:<base64url-no-padding>` SPKI hash. Set by `accept`
    /// (extracted from the admin-signed invite). Vault refuses to
    /// connect without a fingerprint match.
    #[serde(default)]
    pub cert_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            format: default_format(),
        }
    }
}

fn default_level() -> String {
    "info".into()
}
fn default_format() -> String {
    "json".into()
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct CliOverrides {
    pub data_dir: Option<PathBuf>,
    pub hub_url: Option<String>,
    pub cert_fingerprint: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct InitOverrides {
    pub data_dir: Option<PathBuf>,
    pub hub_url: Option<String>,
}

impl VaultConfig {
    /// Load with full layering. CLI overrides win, then env, then
    /// TOML, then defaults.
    ///
    /// # Errors
    ///
    /// Returns `anyhow::Error` on missing / malformed fields.
    pub fn load(config_path: Option<&Path>, cli: CliOverrides) -> anyhow::Result<Self> {
        let path = match config_path {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };
        let mut fig = Figment::new().merge(Serialized::defaults(VaultConfig::default()));
        if path.exists() {
            fig = fig.merge(Toml::file(&path));
        }
        fig = fig.merge(Env::prefixed("VITONOMI_VAULT_").split("__"));
        let cli_value =
            serde_json::to_value(&cli).map_err(|e| anyhow!("serialize CLI overrides: {e}"))?;
        if let serde_json::Value::Object(map) = cli_value {
            let mut paths = serde_json::Map::new();
            let mut hub = serde_json::Map::new();
            for (k, v) in map {
                if v.is_null() {
                    continue;
                }
                match k.as_str() {
                    "data_dir" => {
                        paths.insert(k, v);
                    }
                    "hub_url" => {
                        hub.insert("url".into(), v);
                    }
                    "cert_fingerprint" => {
                        hub.insert("cert_fingerprint".into(), v);
                    }
                    _ => {}
                }
            }
            let mut nested = serde_json::Map::new();
            if !paths.is_empty() {
                nested.insert("paths".into(), serde_json::Value::Object(paths));
            }
            if !hub.is_empty() {
                nested.insert("hub".into(), serde_json::Value::Object(hub));
            }
            if !nested.is_empty() {
                fig = fig.merge(Serialized::defaults(serde_json::Value::Object(nested)));
            }
        }
        fig.extract().context("invalid vault config")
    }

    /// Persist this config as TOML.
    ///
    /// # Errors
    ///
    /// File-system / serialisation failures.
    pub fn write_to(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create config dir {}", parent.display()))?;
        }
        let toml = toml::to_string_pretty(self).context("serialize vault config")?;
        std::fs::write(path, toml).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}

/// Default config-file location: `$XDG_CONFIG_HOME/vitonomi/vault.toml`.
///
/// # Errors
///
/// `anyhow::Error` if no config home can be resolved on this platform.
pub fn default_config_path() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "vitonomi", "vitonomi")
        .ok_or_else(|| anyhow!("cannot resolve $XDG_CONFIG_HOME for vitonomi"))?;
    Ok(dirs.config_dir().join("vault.toml"))
}

/// Initialise `tracing` for the running binary.
pub fn init_logging() {
    let filter = EnvFilter::try_from_env("VITONOMI_LOG")
        .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_current_span(false))
        .try_init();
}

/// Write a default config (interactively or via CLI flags). Refuses
/// to overwrite an existing config unless `force` is set.
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
    let mut cfg = VaultConfig::default();
    if let Some(d) = overrides.data_dir {
        cfg.paths.data_dir = d;
    }
    if let Some(u) = overrides.hub_url {
        cfg.hub.url = u;
    }
    cfg.write_to(&path)?;
    eprintln!("wrote default config: {}", path.display());
    Ok(())
}
