//! `vitonomi-mx` — log-free, RAM-only SMTP relay.
//!
//! Receives inbound mail on port 25, encrypts the body in RAM
//! against the alias's published ML-KEM-768 pubkey via
//! [`vitonomi_core::crypto::alias_inbound`], and pushes the
//! ciphertext envelope to the user's hub. Plaintext never reaches
//! the disk and never appears in logs.
//!
//! See `../docs/architecture.md` for the mx relay's place in the
//! trust topology and `../PROJECT.md` for the deliverable list.

#![forbid(unsafe_code)]

pub mod cli;
pub mod commands;
pub mod config;
pub mod dispatch;
pub mod hub_client;
pub mod identity;
pub mod operability;
pub mod smtp;
pub mod state_dir;
pub mod tls;

pub use config::MxConfig;
