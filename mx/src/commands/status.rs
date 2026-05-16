//! `vitonomi-mx status` — print the loaded config to stdout.
//!
//! Useful for verifying that `--config <path>` + env-var
//! overrides + CLI flags merge correctly, without booting the
//! SMTP listener. Intentionally one-line-per-field so callers
//! can `grep` the output in tests / shell scripts.

use crate::config::MxConfig;

/// Pretty-print the loaded config.
///
/// # Errors
///
/// Currently infallible; signature returns `anyhow::Result` for
/// future-proofing (e.g. for future mx-identity inspection that
/// wants to print the fingerprint).
#[allow(clippy::print_stdout)]
pub fn run(cfg: &MxConfig) -> anyhow::Result<()> {
    println!("server.bind_addr   = {}", cfg.server.bind_addr);
    println!("server.port        = {}", cfg.server.port);
    println!("server.base_domain = {}", cfg.server.base_domain);
    println!("hub.url            = {}", cfg.hub.url);
    println!("paths.data_dir     = {}", cfg.paths.data_dir.display());
    println!("logging.level      = {}", cfg.logging.level);
    println!("logging.format     = {}", cfg.logging.format);
    Ok(())
}
