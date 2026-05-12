//! Wire-format structs. Each submodule mirrors a logical surface
//! (login, accept-invite, vault-bus, admin-chain).

pub mod accept;
pub mod admin_chain;
pub mod bootstrap;
pub mod data_plane;
pub mod login;
pub mod rendezvous;
pub mod vault_bus;
