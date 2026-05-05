//! `vitonomi-hub` — control-plane server. Designed under the
//! hub-blindness invariant: every byte the hub stores is either an
//! allow-listed plaintext field (cluster_id, public keys, opaque
//! ids, connection-observable state, signed envelope shells) or
//! AEAD-sealed under a key the hub never sees.
//!
//! See `../docs/architecture.md#hub-blindness-trust-topology` for
//! the trust topology and `../docs/api-spec.yaml` for the HTTP
//! surface.

#![forbid(unsafe_code)]

pub mod auth;
pub mod cli;
pub mod config;
pub mod routes;
pub mod server;
pub mod state;
pub mod tls;
pub mod ws;

pub use config::HubConfig;
pub use server::{run, run_with_listener};
