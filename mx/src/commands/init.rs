//! `vitonomi-mx init` — write a default `mx.toml` and mint the
//! ML-DSA-65 relay identity. The pubkey hex is printed to stdout
//! (single line, lowercase) so it can be captured directly:
//!
//! ```bash
//! PUB=$(vitonomi-mx init --base vito.gg --hub https://hub.example/ ...)
//! # transmit $PUB out-of-band to the admin, who runs:
//! #   vitonomi-cli mx register --pubkey "$PUB" --namespace vito.gg
//! # then back on the relay box:
//! #   vitonomi-mx start
//! ```
//!
//! Status messages go to stderr so `$()` capture of the pubkey
//! stays clean.

use std::path::Path;

use anyhow::Context as _;

use vitonomi_core::encoding::hex_encode;

use crate::config::{write_default_config, InitOverrides, MxConfig};
use crate::identity::load_or_generate;
use crate::state_dir;

/// Write a fresh `mx.toml` then mint the relay identity. Prints the
/// hex-encoded ML-DSA-65 pubkey to stdout, status to stderr.
///
/// # Errors
///
/// File-system, config-serialization, or crypto failures.
#[allow(clippy::print_stdout, clippy::print_stderr)]
pub fn run(
    config_path: Option<&Path>,
    overrides: InitOverrides,
    force: bool,
) -> anyhow::Result<()> {
    write_default_config(config_path, overrides, force).context("write default config")?;

    let cfg = MxConfig::load(config_path, crate::config::CliOverrides::default())
        .context("reload freshly-written config")?;
    state_dir::ensure_data_dir(&cfg.paths.data_dir)?;
    let identity = load_or_generate(&cfg.paths.data_dir).context("mint relay identity")?;
    eprintln!("minted relay identity at {}", cfg.paths.data_dir.display());
    eprintln!(
        "next: transmit the pubkey below to a cluster admin, who runs"
    );
    eprintln!(
        "      vitonomi-cli mx register --pubkey <PUB> --namespace <NS>"
    );
    eprintln!("then on this box: vitonomi-mx start");
    println!("{}", hex_encode(identity.public.as_bytes()));
    Ok(())
}
