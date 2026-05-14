//! Credential-specific helpers consumed by the CLI / PWA on top of
//! the per-RecordType schemas in `core::types::credential`.
//!
//! - [`password_gen`]: cryptographically-strong password generator.
//! - [`import`]: file → `Vec<(CredentialMetadata, CredentialBody)>`
//!   parsers for 1Password CSV, Bitwarden JSON, Chrome CSV,
//!   KeePassXC CSV.
//! - [`export`]: `Vec<(CredentialMetadata, CredentialBody)>` →
//!   encrypted vitonomi-backup or plaintext JSON.

pub mod export;
pub mod import;
pub mod password_gen;
