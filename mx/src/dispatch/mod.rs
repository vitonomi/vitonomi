//! Post-DATA orchestration: alias-directory lookup + AEAD seal
//!   + signed hub push. Called once per inbound message after
//!   the DATA phase ends.

pub mod alias_lookup;
pub mod hub_push;
