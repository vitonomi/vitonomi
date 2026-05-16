//! Layered config: defaults → TOML file → env (`VITONOMI_MX_*`) →
//! CLI overrides. Loaded by [`MxConfig::load`].
//!
//! Fields today: hub URL, base domain, bind addr/port, data dir,
//! TLS PEM paths, logging. Multi-base / multi-domain acceptance
//! lists are future-work.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MxConfig {
    pub server: ServerConfig,
    pub hub: HubConfig,
    pub paths: PathsConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to wildcard cert PEM. Blank → dev mode generates
    /// `<data_dir>/tls/cert.pem` via rcgen.
    #[serde(default)]
    pub cert_pem: String,
    /// Path to wildcard key PEM. Blank → dev mode generates
    /// `<data_dir>/tls/key.pem` via rcgen.
    #[serde(default)]
    pub key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// SMTP listen address. Production binds `0.0.0.0` on port 25;
    /// dev/CI uses `127.0.0.1` on an ephemeral port.
    pub bind_addr: String,
    /// SMTP listen port. Default 25 in production; 0 = ephemeral
    /// (kernel-picked) in tests.
    pub port: u16,
    /// Base domain the mx relay is authoritative for (e.g.
    /// `vito.gg` or `inbox.example.com`). A single base today;
    /// multi-base + separate `accept_domains` list are future-work.
    pub base_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubConfig {
    /// HTTPS URL of the hub the mx relay pushes inbound ciphertext
    /// to (e.g. `https://hub.vitonomi.com`).
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    /// Persistent state — mx-relay ML-DSA-65 identity, dev TLS
    /// cert, small caches.
    pub data_dir: PathBuf,
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
    pub bind_addr: Option<String>,
    pub port: Option<u16>,
    pub data_dir: Option<PathBuf>,
    pub hub_url: Option<String>,
    pub base_domain: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct InitOverrides {
    pub bind_addr: Option<String>,
    pub port: Option<u16>,
    pub data_dir: Option<PathBuf>,
    pub hub_url: Option<String>,
    pub base_domain: Option<String>,
}

impl MxConfig {
    /// Load with full layering. CLI overrides win, then env
    /// (`VITONOMI_MX_*`), then TOML file, then defaults.
    ///
    /// # Errors
    ///
    /// Missing required fields, file read errors, environment
    /// parse errors.
    pub fn load(config_path: Option<&Path>, cli: CliOverrides) -> anyhow::Result<Self> {
        let path = match config_path {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };
        let mut fig = Figment::new().merge(Serialized::defaults(default_config()));
        if path.exists() {
            fig = fig.merge(Toml::file(&path));
        }
        fig = fig.merge(Env::prefixed("VITONOMI_MX_").split("__"));

        let cli_overrides =
            serde_json::to_value(&cli).map_err(|e| anyhow!("serialize CLI overrides: {e}"))?;
        if let serde_json::Value::Object(map) = cli_overrides {
            let mut applied = serde_json::Map::new();
            for (k, v) in map {
                if !v.is_null() {
                    applied.insert(k, v);
                }
            }
            if !applied.is_empty() {
                let json = serde_json::Value::Object(nest_cli_fields(applied));
                fig = fig.merge(Serialized::defaults(json));
            }
        }
        let cfg: Self = fig.extract().context("invalid mx config")?;
        Ok(cfg)
    }
}

fn nest_cli_fields(
    map: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    let mut server = serde_json::Map::new();
    let mut paths = serde_json::Map::new();
    let mut hub = serde_json::Map::new();
    for (k, v) in map {
        match k.as_str() {
            "bind_addr" | "port" | "base_domain" => {
                server.insert(k, v);
            }
            "data_dir" => {
                paths.insert(k, v);
            }
            "hub_url" => {
                hub.insert("url".into(), v);
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
    if !hub.is_empty() {
        out.insert("hub".into(), serde_json::Value::Object(hub));
    }
    out
}

fn default_config() -> MxConfig {
    MxConfig {
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            port: 25,
            base_domain: "vito.gg".into(),
        },
        hub: HubConfig {
            url: "https://hub.vitonomi.com".into(),
        },
        paths: PathsConfig {
            data_dir: default_data_dir(),
        },
        tls: TlsConfig::default(),
        logging: LoggingConfig {
            level: default_level(),
            format: default_format(),
        },
    }
}

fn default_data_dir() -> PathBuf {
    directories::ProjectDirs::from("com", "vitonomi", "vitonomi")
        .map(|d| d.data_dir().join("mx"))
        .unwrap_or_else(|| PathBuf::from("./vitonomi-mx-data"))
}

/// Default config-file location: `$XDG_CONFIG_HOME/vitonomi/mx.toml`.
///
/// # Errors
///
/// Returns an error if no config home can be resolved on this platform.
pub fn default_config_path() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "vitonomi", "vitonomi")
        .ok_or_else(|| anyhow!("cannot resolve $XDG_CONFIG_HOME for vitonomi"))?;
    Ok(dirs.config_dir().join("mx.toml"))
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

/// Write a default config file. Refuses to overwrite unless
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
        return Err(anyhow!(
            "config file already exists at {} — pass --force to overwrite",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir {}", parent.display()))?;
    }

    let mut cfg = default_config();
    if let Some(addr) = overrides.bind_addr {
        cfg.server.bind_addr = addr;
    }
    if let Some(port) = overrides.port {
        cfg.server.port = port;
    }
    if let Some(base) = overrides.base_domain {
        cfg.server.base_domain = base;
    }
    if let Some(url) = overrides.hub_url {
        cfg.hub.url = url;
    }
    if let Some(dir) = overrides.data_dir {
        cfg.paths.data_dir = dir;
    }

    let toml_str = toml::to_string_pretty(&cfg).context("serialize default mx config to TOML")?;
    std::fs::write(&path, toml_str).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips_through_toml() {
        let cfg = default_config();
        let s = toml::to_string_pretty(&cfg).unwrap();
        let back: MxConfig = toml::from_str(&s).unwrap();
        assert_eq!(back.server.bind_addr, cfg.server.bind_addr);
        assert_eq!(back.server.port, cfg.server.port);
        assert_eq!(back.server.base_domain, cfg.server.base_domain);
        assert_eq!(back.hub.url, cfg.hub.url);
        assert_eq!(back.paths.data_dir, cfg.paths.data_dir);
    }

    #[test]
    fn write_default_config_refuses_existing_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("mx.toml");
        write_default_config(Some(&p), InitOverrides::default(), false).unwrap();
        let err = write_default_config(Some(&p), InitOverrides::default(), false).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn write_default_config_overrides_apply() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("mx.toml");
        write_default_config(
            Some(&p),
            InitOverrides {
                bind_addr: Some("0.0.0.0".into()),
                port: Some(2525),
                base_domain: Some("example.test".into()),
                hub_url: Some("https://hub.example.test".into()),
                data_dir: Some(tmp.path().join("data")),
            },
            true,
        )
        .unwrap();
        let cfg: MxConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(cfg.server.bind_addr, "0.0.0.0");
        assert_eq!(cfg.server.port, 2525);
        assert_eq!(cfg.server.base_domain, "example.test");
        assert_eq!(cfg.hub.url, "https://hub.example.test");
        assert_eq!(cfg.paths.data_dir, tmp.path().join("data"));
    }

    #[test]
    fn load_picks_up_cli_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("mx.toml");
        write_default_config(Some(&p), InitOverrides::default(), false).unwrap();
        let cfg = MxConfig::load(
            Some(&p),
            CliOverrides {
                port: Some(2525),
                bind_addr: Some("0.0.0.0".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(cfg.server.port, 2525);
        assert_eq!(cfg.server.bind_addr, "0.0.0.0");
    }
}
