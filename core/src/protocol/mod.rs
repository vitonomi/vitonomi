//! Wire-format types and trait surfaces for the hub control plane,
//! the vault-bus session, and the (stubbed) Autonomi bridge.
//!
//! `wire/*` defines the actual on-wire structs (CBOR + JSON via
//! serde). The traits in `hub_control_plane.rs` and `vault_bus.rs`
//! abstract over the transport so the hub-, vault-, and CLI-side
//! code can be tested with the in-memory implementations under
//! `testing/`.

pub mod autonomi_bridge;
pub mod hub_control_plane;
pub mod testing;
pub mod vault_bus;
pub mod vault_storage;
pub mod wire;
