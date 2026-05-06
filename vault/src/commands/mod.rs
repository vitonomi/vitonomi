//! Subcommand dispatchers. Each is a thin wrapper that loads
//! config + identity / state, then delegates to the relevant
//! module.

pub mod accept;
pub mod info;
pub mod init;
pub mod set_hub;
pub mod start;
pub mod status;
