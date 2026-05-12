//! Cryptographic primitives. Every operation that requires a key,
//! signature, or hash flows through this module — daemons / CLIs
//! consume the higher-level helpers here without depending on
//! `argon2`, `chacha20poly1305`, `pqcrypto-*`, etc. directly.

pub mod admin_chain;
pub mod aead;
pub mod argon2;
pub mod challenge;
pub mod cluster;
pub mod cluster_keys;
pub mod invite_kek;
pub mod keyblob;
pub mod keys;
pub mod lookup_id;
pub mod pq;
pub mod random;
pub mod seedphrase;
pub mod selfencrypt;
pub mod spki;
