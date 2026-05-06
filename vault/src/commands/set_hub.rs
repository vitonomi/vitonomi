//! `vitonomi-vault set-hub --url <new-url> --fingerprint <fp>` —
//! re-point the vault at a new hub.

use std::path::Path;

use crate::config::VaultConfig;

pub async fn run(
    config_path: &Path,
    mut cfg: VaultConfig,
    url: &str,
    fingerprint: &str,
) -> anyhow::Result<()> {
    crate::set_hub::run(config_path, &mut cfg, url, fingerprint).await
}
