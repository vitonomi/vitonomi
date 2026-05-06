//! `vitonomi-cli init --hub <url>` — write a default `cli.toml`.

use std::path::Path;
use std::path::PathBuf;

use crate::config::{write_default_config, InitOverrides};

pub fn run(
    config_path: Option<&Path>,
    hub_url: Option<String>,
    state_dir: Option<PathBuf>,
    force: bool,
) -> anyhow::Result<()> {
    write_default_config(config_path, InitOverrides { hub_url, state_dir }, force)
}
