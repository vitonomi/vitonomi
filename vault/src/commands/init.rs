//! `vitonomi-vault init` — write a default `vault.toml`.

use std::path::Path;
use std::path::PathBuf;

use crate::config::{write_default_config, InitOverrides};

#[allow(clippy::needless_pass_by_value)]
pub fn run(
    config_path: Option<&Path>,
    data_dir: Option<PathBuf>,
    hub_url: Option<String>,
    force: bool,
) -> anyhow::Result<()> {
    write_default_config(config_path, InitOverrides { data_dir, hub_url }, force)
}
