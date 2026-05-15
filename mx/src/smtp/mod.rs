//! SMTP receiver — `mailin-embedded` Handler trait impl with
//! the vitonomi-mx privacy semantics:
//! - 250-OK on every `RCPT TO` regardless of address validity
//!   (alias-existence check moves to the post-DATA hub-push
//!   step; silent-drop on miss).
//! - DATA-phase plaintext buffered in RAM only, zeroized
//!   before the session function returns. No file writes.
//! - Per-base-domain metrics; never per-alias.

pub mod encryptor_stream;
pub mod handler;
pub mod server;
