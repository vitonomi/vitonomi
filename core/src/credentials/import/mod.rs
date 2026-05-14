//! Credential importers — parse export files from popular password
//! managers into the vitonomi `(CredentialMetadata, CredentialBody)`
//! pair.
//!
//! Every importer is a pure function over `impl Read`. No
//! filesystem traversal, no network, no clock dependency.
//!
//! Format notes (verify against a real export from each tool
//! before trusting in production — vendor formats drift):
//!
//! - **1Password CSV**: `Title,Url,Username,Password,OTPAuth,Notes,Tags,Type`
//!   (column set + order matches recent 1Password 8.x exports).
//! - **Bitwarden JSON**: the unencrypted JSON export (Tools →
//!   Export Vault → File format `.json` with "Password protect
//!   your export" left unchecked).
//! - **Chrome CSV**: `name,url,username,password,note` (newer
//!   Chromium versions add the trailing `note` column).
//! - **KeePassXC CSV**: `"Group","Title","Username","Password",
//!   "URL","Notes","TOTP","Icon","Last Modified","Created"`
//!   (Database → Export → CSV in current KeePassXC builds).
//!
//! Each parser sanity-checks the header row and errors with a
//! helpful message on column-name drift; reporting that error
//! gives the implementer a clear signal to update the parser to
//! match the user's actual export.

use std::io::Read;

use crate::errors::ProtocolError;
use crate::types::credential::{CredentialBody, CredentialMetadata};

pub mod bitwarden;
pub mod chrome;
pub mod keepass_xc;
pub mod one_password;

/// Which importer to invoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    OnePasswordCsv,
    BitwardenJson,
    ChromeCsv,
    KeepassXcCsv,
}

/// One row produced by an importer: a paired (metadata, body) ready
/// to feed into `RecordStore::put` with `BodyOp::Set`.
pub type ImportedCredential = (CredentialMetadata, CredentialBody);

/// Parse an export file. Returns the credentials in the order they
/// appear in the source.
///
/// # Errors
///
/// `ProtocolError::Malformed` for any structural problem (bad
/// header row, malformed JSON, malformed CSV, decoding failure).
pub fn import<R: Read>(
    format: ImportFormat,
    reader: R,
) -> Result<Vec<ImportedCredential>, ProtocolError> {
    match format {
        ImportFormat::OnePasswordCsv => one_password::from_reader(reader),
        ImportFormat::BitwardenJson => bitwarden::from_reader(reader),
        ImportFormat::ChromeCsv => chrome::from_reader(reader),
        ImportFormat::KeepassXcCsv => keepass_xc::from_reader(reader),
    }
}
