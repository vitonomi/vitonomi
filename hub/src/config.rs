//! Layered config: defaults → TOML file → env (`VITONOMI_HUB_*`) →
//! CLI overrides. Loaded by `HubConfig::load`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    pub server: ServerConfig,
    pub paths: PathsConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub port: u16,
    #[serde(default)]
    pub single_user: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    pub data_dir: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to PEM cert. If both fields blank, dev mode auto-
    /// generates a self-signed cert in `data_dir`.
    #[serde(default)]
    pub cert_pem: String,
    #[serde(default)]
    pub key_pem: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_level() -> String {
    "info".into()
}
fn default_format() -> String {
    "json".into()
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct CliOverrides {
    pub port: Option<u16>,
    pub bind_addr: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub single_user: Option<bool>,
}

#[derive(Debug, Default, Clone)]
pub struct InitOverrides {
    pub bind_addr: Option<String>,
    pub port: Option<u16>,
    pub data_dir: Option<PathBuf>,
    pub single_user: bool,
}

impl HubConfig {
    /// Load config with full layering. CLI overrides win, then env
    /// (`VITONOMI_HUB_*`), then TOML file, then defaults.
    ///
    /// # Errors
    ///
    /// Returns `anyhow::Error` on missing required fields, file
    /// read errors, or environment parse errors.
    pub fn load(config_path: Option<&Path>, cli: CliOverrides) -> anyhow::Result<Self> {
        let path = match config_path {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };
        let mut fig = Figment::new().merge(Serialized::defaults(default_config()));
        if path.exists() {
            fig = fig.merge(Toml::file(&path));
        }
        fig = fig.merge(Env::prefixed("VITONOMI_HUB_").split("__"));
        // Apply CLI overrides only for explicitly-set fields.
        let cli_overrides =
            serde_json::to_value(&cli).map_err(|e| anyhow!("serialize CLI overrides: {e}"))?;
        if let serde_json::Value::Object(map) = cli_overrides {
            let mut applied = serde_json::Map::new();
            for (k, v) in map {
                if !v.is_null() {
                    applied.insert(map_cli_field(&k), v);
                }
            }
            if !applied.is_empty() {
                let json = serde_json::Value::Object(nest_cli_fields(applied));
                fig = fig.merge(Serialized::defaults(json));
            }
        }
        let cfg: Self = fig.extract().context("invalid hub config")?;
        Ok(cfg)
    }
}

fn map_cli_field(k: &str) -> String {
    // CLI keys are flat (port, bind_addr, etc.). Map them to their
    // nested location under `server.*` / `paths.*`.
    match k {
        "port" | "bind_addr" | "single_user" => k.to_string(),
        "data_dir" => k.to_string(),
        other => other.to_string(),
    }
}

fn nest_cli_fields(
    map: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    let mut server = serde_json::Map::new();
    let mut paths = serde_json::Map::new();
    for (k, v) in map {
        match k.as_str() {
            "port" | "bind_addr" | "single_user" => {
                server.insert(k, v);
            }
            "data_dir" => {
                paths.insert(k, v);
            }
            other => {
                out.insert(other.to_string(), v);
            }
        }
    }
    if !server.is_empty() {
        out.insert("server".into(), serde_json::Value::Object(server));
    }
    if !paths.is_empty() {
        out.insert("paths".into(), serde_json::Value::Object(paths));
    }
    out
}

fn default_config() -> HubConfig {
    HubConfig {
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            port: 4443,
            single_user: false,
        },
        paths: PathsConfig {
            data_dir: PathBuf::from("/var/lib/vitonomi-hub"),
        },
        tls: TlsConfig::default(),
        logging: LoggingConfig {
            level: default_level(),
            format: default_format(),
        },
    }
}

/// Default config-file location: `$XDG_CONFIG_HOME/vitonomi/hub.toml`.
///
/// # Errors
///
/// Returns an error if no config home can be resolved on this platform.
pub fn default_config_path() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "vitonomi", "vitonomi")
        .ok_or_else(|| anyhow!("cannot resolve $XDG_CONFIG_HOME for vitonomi"))?;
    Ok(dirs.config_dir().join("hub.toml"))
}

/// Initialise `tracing` for the running binary. Respects
/// `VITONOMI_LOG` / `RUST_LOG`.
pub fn init_logging() {
    let filter = EnvFilter::try_from_env("VITONOMI_LOG")
        .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_current_span(false))
        .try_init();
}

/// Write a default config to disk. Refuses to overwrite unless
/// `force` is true.
///
/// # Errors
///
/// File-system errors, parent-directory creation failure, or an
/// existing config when `force` is false.
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
            "{} already exists; use `--force` to overwrite",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create config dir {}", parent.display()))?;
    }
    let mut cfg = default_config();
    if let Some(b) = overrides.bind_addr {
        cfg.server.bind_addr = b;
    }
    if let Some(p) = overrides.port {
        cfg.server.port = p;
    }
    if let Some(d) = overrides.data_dir {
        cfg.paths.data_dir = d;
    }
    if overrides.single_user {
        cfg.server.single_user = true;
    }
    let toml = toml::to_string_pretty(&cfg).context("serialize default config")?;
    std::fs::write(&path, toml).with_context(|| format!("write {}", path.display()))?;
    eprintln!("wrote default config: {}", path.display());
    Ok(())
}
