//! Phase 7 Slice 0 acceptance test.
//!
//! `vitonomi-mx init` with overrides writes a `mx.toml` that
//! parses cleanly back into [`MxConfig`].

use vitonomi_mx::config::{
    write_default_config, InitOverrides, MxConfig,
};

#[test]
fn init_writes_a_parseable_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("mx.toml");

    write_default_config(
        Some(&path),
        InitOverrides {
            bind_addr: Some("0.0.0.0".into()),
            port: Some(2525),
            base_domain: Some("inbox.example.test".into()),
            hub_url: Some("https://hub.example.test".into()),
            data_dir: Some(tmp.path().join("data")),
        },
        false,
    )
    .expect("init writes a default config");

    let toml_str = std::fs::read_to_string(&path).expect("config file readable");
    let cfg: MxConfig = toml::from_str(&toml_str).expect("config parses as MxConfig");
    assert_eq!(cfg.server.bind_addr, "0.0.0.0");
    assert_eq!(cfg.server.port, 2525);
    assert_eq!(cfg.server.base_domain, "inbox.example.test");
    assert_eq!(cfg.hub.url, "https://hub.example.test");
    assert_eq!(cfg.paths.data_dir, tmp.path().join("data"));
}
