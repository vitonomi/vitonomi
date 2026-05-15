//! Phase 7 Slice 0 acceptance test.
//!
//! `vitonomi-mx status` prints the loaded config so an operator
//! can verify CLI / env-var merging without booting the SMTP
//! listener. We exercise the library entrypoint directly so the
//! test doesn't need the binary on PATH.

use vitonomi_mx::commands::status;
use vitonomi_mx::config::{
    write_default_config, InitOverrides, MxConfig,
};

#[test]
fn status_runs_against_a_loaded_config_without_panicking() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("mx.toml");
    write_default_config(
        Some(&path),
        InitOverrides {
            base_domain: Some("vito.gg".into()),
            hub_url: Some("https://hub.vitonomi.com".into()),
            data_dir: Some(tmp.path().join("data")),
            ..Default::default()
        },
        false,
    )
    .unwrap();

    let cfg = MxConfig::load(Some(&path), Default::default()).expect("load default config");
    // status::run prints to stdout and returns Ok. We're not
    // capturing stdout here (cargo test captures by default;
    // verifying *content* would require reqwest-style stdout
    // capture); the contract for slice 0 is just "does not
    // panic on a valid config".
    status::run(&cfg).expect("status runs cleanly");
}
