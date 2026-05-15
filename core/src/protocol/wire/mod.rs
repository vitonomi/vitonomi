//! Wire-format structs. Each submodule mirrors a logical surface
//! (login, accept-invite, vault-bus, admin-chain, …).

pub mod accept;
pub mod admin_chain;
pub mod aliases;
pub mod bootstrap;
pub mod data_plane;
pub mod domains;
pub mod login;
pub mod relay_push;
pub mod rendezvous;
pub mod subdomains;
pub mod vault_bus;
