//! vitonomi shared crate.
//!
//! Houses cryptographic primitives, protocol traits, and shared types
//! used by every other workspace member (vault, hub, mx, vito-cli,
//! clients/cli) plus the WASM bridge consumed by `clients/web`.
//!
//! See `~/.claude/plans/` and the workspace `PROJECT.md` for the
//! work breakdown that produced this crate.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod encoding;
pub mod errors;
pub mod logging;
pub mod protocol;
pub mod types;

pub use errors::{AuthError, CoreError, CryptoError, NetworkError, ProtocolError, ValidationError};
pub use types::{ClusterId, FormatVersion, Result, SessionToken, UserId, Username, VaultId};
