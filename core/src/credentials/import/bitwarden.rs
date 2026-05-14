//! Bitwarden JSON importer (unencrypted export).
//!
//! Bitwarden's export schema (Tools → Export Vault → File format
//! `.json`, leave "Password protect your export" unchecked):
//!
//! ```json
//! {
//!   "items": [
//!     {
//!       "type": 1,                       // 1 = login
//!       "name": "GitHub",
//!       "notes": "...",
//!       "favorite": false,
//!       "folderId": "uuid-or-null",
//!       "login": {
//!         "username": "birkeal",
//!         "password": "hunter2",
//!         "totp": "otpauth://...",
//!         "uris": [{"uri": "https://github.com"}]
//!       }
//!     }
//!   ],
//!   "folders": [{"id": "uuid", "name": "Work"}]
//! }
//! ```
//!
//! Encrypted exports are NOT supported; the user must export
//! unprotected.

use std::io::Read;

use serde::Deserialize;

use crate::errors::ProtocolError;
use crate::totp::parse_otpauth_uri;
use crate::types::credential::{
    CredentialBody, CredentialMetadata, SecretString,
};
use crate::types::FormatVersion;

use super::ImportedCredential;

#[derive(Debug, Deserialize)]
struct Export {
    items: Vec<Item>,
    #[serde(default)]
    folders: Vec<Folder>,
}

#[derive(Debug, Deserialize)]
struct Folder {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct Item {
    #[serde(rename = "type")]
    item_type: u8,
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default, rename = "folderId")]
    folder_id: Option<String>,
    #[serde(default)]
    login: Option<Login>,
}

#[derive(Debug, Deserialize)]
struct Login {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<Uri>,
}

#[derive(Debug, Deserialize)]
struct Uri {
    uri: String,
}

/// Parse a Bitwarden unencrypted JSON export.
///
/// # Errors
///
/// `ProtocolError::Malformed` if the JSON is malformed or missing
/// required fields. Encrypted exports cannot be parsed.
pub fn from_reader<R: Read>(reader: R) -> Result<Vec<ImportedCredential>, ProtocolError> {
    let export: Export = serde_json::from_reader(reader)
        .map_err(|e| ProtocolError::Malformed(format!("bitwarden JSON: {e}")))?;
    let folder_lookup: std::collections::HashMap<String, String> = export
        .folders
        .iter()
        .map(|f| (f.id.clone(), f.name.clone()))
        .collect();

    let mut out = Vec::new();
    for item in export.items {
        // Only login (type 1) entries — skip secure-notes, cards,
        // identities. (We can extend later if asked.)
        if item.item_type != 1 {
            continue;
        }
        let folder = item
            .folder_id
            .as_ref()
            .and_then(|id| folder_lookup.get(id).cloned());
        let login = item.login.unwrap_or(Login {
            username: None,
            password: None,
            totp: None,
            uris: Vec::new(),
        });
        let url = login.uris.first().map(|u| u.uri.clone());
        let totp = login.totp.as_ref().and_then(|s| {
            if s.starts_with("otpauth://") {
                parse_otpauth_uri(s).ok().map(|(_, cfg)| cfg)
            } else {
                // Bitwarden also stores raw base32 secrets here;
                // wrap with a minimal otpauth URI so the existing
                // parser handles it.
                let synth = format!("otpauth://totp/imported?secret={s}");
                parse_otpauth_uri(&synth).ok().map(|(_, cfg)| cfg)
            }
        });
        let has_totp = totp.is_some();

        out.push((
            CredentialMetadata {
                format_version: FormatVersion::V1,
                title: item.name,
                url,
                username: login.username,
                tags: Vec::new(),
                folder,
                has_totp,
                created_at_ms: 0,
                updated_at_ms: 0,
            },
            CredentialBody {
                format_version: FormatVersion::V1,
                password: SecretString::new(login.password.unwrap_or_default()),
                totp,
                notes: item.notes,
                custom_fields: Vec::new(),
            },
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
        "folders": [
            {"id": "f1", "name": "Work"}
        ],
        "items": [
            {
                "type": 1,
                "name": "GitHub",
                "notes": "deploy keys here",
                "folderId": "f1",
                "login": {
                    "username": "birkeal",
                    "password": "hunter2",
                    "totp": "otpauth://totp/GitHub?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30",
                    "uris": [{"uri": "https://github.com"}]
                }
            },
            {
                "type": 2,
                "name": "Some Secure Note",
                "notes": "skip me"
            },
            {
                "type": 1,
                "name": "Netflix",
                "login": {
                    "username": "birkeal",
                    "password": "couch_potato",
                    "uris": [{"uri": "https://netflix.com"}]
                }
            }
        ]
    }"#;

    #[test]
    fn parses_only_login_items() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        assert_eq!(creds.len(), 2, "secure-note item should be skipped");
        assert_eq!(creds[0].0.title, "GitHub");
        assert_eq!(creds[1].0.title, "Netflix");
    }

    #[test]
    fn maps_folder_via_lookup() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        assert_eq!(creds[0].0.folder.as_deref(), Some("Work"));
        assert!(creds[1].0.folder.is_none());
    }

    #[test]
    fn maps_totp_via_otpauth_uri() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        assert!(creds[0].0.has_totp);
        assert!(creds[0].1.totp.is_some());
        assert!(!creds[1].0.has_totp);
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(from_reader(b"{".as_slice()).is_err());
    }
}
