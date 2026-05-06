//! `vitonomi-vault` — persistent storage daemon. Holds the cluster
//! shared key (received via the K2 invite inner payload) and
//! maintains a long-lived authenticated WebSocket session to the
//! hub.
//!
//! Per the hub-blindness invariant, the vault is the canonical
//! holder of the admin chain (the hub's chain copy is advisory
//! cache). On every reconnect it verifies what the hub serves
//! against its local copy and surfaces mismatches.

#![forbid(unsafe_code)]

pub mod accept;
pub mod chain_store;
pub mod cli;
pub mod commands;
pub mod config;
pub mod hub_client;
pub mod identity;
pub mod set_hub;
pub mod state_dir;
