//! `vitonomi-cli` — admin CLI client. Owns the cluster admin
//! secret keys (recovered from the encrypted key blob on each
//! invocation that needs them) and drives the hub-blind auth slice.
//!
//! Lib + bin split so integration tests can drive subcommands
//! without a subprocess.

#![forbid(unsafe_code)]

pub mod cli;
pub mod commands;
pub mod config;
pub mod hub_client;
pub mod p2p;
pub mod prompts;
pub mod state;
