//! `vitonomi-mx pubkey` — print the relay's ML-DSA-65 public key in
//! hex. Idempotent: loads `<data_dir>/identity.bin` if present, mints
//! a fresh keypair (with the same atomic-write + 0600 perms as
//! `start`) if not.
//!
//! Used as the bridge between the relay box and the admin running
//! `vitonomi-cli mx register --pubkey <hex>`.

use anyhow::Context as _;

use vitonomi_core::encoding::hex_encode;

use crate::config::MxConfig;
use crate::identity::load_or_generate;
use crate::state_dir;

/// Run.
///
/// # Errors
///
/// File-system or crypto failures.
#[allow(clippy::print_stdout)]
pub fn run(cfg: &MxConfig) -> anyhow::Result<()> {
    state_dir::ensure_data_dir(&cfg.paths.data_dir)?;
    let identity = load_or_generate(&cfg.paths.data_dir).context("load or mint relay identity")?;
    println!("{}", hex_encode(identity.public.as_bytes()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HubConfig, LoggingConfig, PathsConfig, ServerConfig, TlsConfig};

    fn cfg_at(data_dir: std::path::PathBuf) -> MxConfig {
        MxConfig {
            server: ServerConfig {
                bind_addr: "127.0.0.1".into(),
                port: 0,
                base_domain: "test.local".into(),
            },
            hub: HubConfig {
                url: "https://hub.test".into(),
            },
            paths: PathsConfig { data_dir },
            tls: TlsConfig::default(),
            logging: LoggingConfig {
                level: "info".into(),
                format: "json".into(),
            },
        }
    }

    #[test]
    fn idempotent_across_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_at(tmp.path().join("data"));
        // First call mints, second call loads the same key.
        run(&cfg).unwrap();
        run(&cfg).unwrap();
        // Pubkey on disk: derive directly and compare to a fresh load.
        let id1 = crate::identity::load_or_generate(&cfg.paths.data_dir).unwrap();
        let id2 = crate::identity::load_or_generate(&cfg.paths.data_dir).unwrap();
        assert_eq!(id1.public.as_bytes(), id2.public.as_bytes());
    }
}
