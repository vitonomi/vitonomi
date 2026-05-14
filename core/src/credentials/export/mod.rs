//! Credential exporters — pair-list → file bytes.
//!
//! - `vitonomi-backup` (the safe path): CBOR-encode the
//!   `Vec<(CredentialMetadata, CredentialBody)>`, AEAD-seal under a
//!   passphrase-derived key (Argon2id + XChaCha20-Poly1305).
//! - `json` (the unsafe path): plaintext JSON. Gated by an
//!   explicit `force_plain` flag the CLI sets only after a
//!   confirm-twice prompt.

pub mod json;
pub mod vitonomi_backup;

use crate::types::credential::{CredentialBody, CredentialMetadata};

pub type ExportItem = (CredentialMetadata, CredentialBody);
