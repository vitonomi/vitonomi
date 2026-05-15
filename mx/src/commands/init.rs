//! `vitonomi-mx init` — write a default `mx.toml`.
//!
//! All real logic lives in [`crate::config::write_default_config`];
//! this module is intentionally empty so the dispatcher in
//! `cli.rs` can call the config helper directly. Future
//! interactive-prompt work (e.g. secret entry for the relay
//! identity passphrase) lands here.
