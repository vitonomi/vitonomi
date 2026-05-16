//! KeePassXC CSV importer.
//!
//! Per the KeePassXC docs, "Database → Export → CSV" produces:
//! `"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"`
//!
//! Vendor formats drift; this parser tolerates absent / extra
//! columns but errors on a missing `Title` column with a clear
//! message that asks the implementer to inspect the actual
//! export.
//!
//! `.kdbx` binary files are NOT supported — users must export to
//! CSV first. (Adding the binary KDBX reader would mean
//! implementing the Argon2-based KDF + a separate audit surface;
//! deferred deliberately.)

use std::io::Read;

use crate::errors::ProtocolError;
use crate::totp::parse_otpauth_uri;
use crate::types::credential::{
    CredentialBody, CredentialMetadata, SecretString,
};
use crate::types::FormatVersion;

use super::ImportedCredential;

/// Parse a KeePassXC CSV export.
///
/// # Errors
///
/// `ProtocolError::Malformed` if the header row lacks `Title`, or
/// a row fails to parse.
pub fn from_reader<R: Read>(reader: R) -> Result<Vec<ImportedCredential>, ProtocolError> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);

    let headers = rdr
        .headers()
        .map_err(|e| ProtocolError::Malformed(format!("csv header read: {e}")))?
        .clone();

    let find = |name: &str| -> Option<usize> {
        headers.iter().position(|h| h.eq_ignore_ascii_case(name))
    };
    let i_title = find("Title").ok_or_else(|| {
        ProtocolError::Malformed(format!(
            "KeePassXC CSV missing required `Title` column. Saw header: \
             [{}]. Expected current KeePassXC schema includes \
             Group,Title,Username,Password,URL,Notes,TOTP. If your \
             KeePassXC version uses different column names, update \
             this parser.",
            headers
                .iter()
                .map(|h| format!("{h:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    let i_group = find("Group");
    let i_user = find("Username");
    let i_pw = find("Password");
    let i_url = find("URL").or_else(|| find("Url"));
    let i_notes = find("Notes");
    let i_totp = find("TOTP");

    let mut out = Vec::new();
    for (line, row) in rdr.records().enumerate() {
        let row = row.map_err(|e| {
            ProtocolError::Malformed(format!("csv row {} parse: {e}", line + 2))
        })?;
        let title = row.get(i_title).unwrap_or_default();
        if title.trim().is_empty() {
            continue;
        }
        let url = i_url
            .and_then(|i| row.get(i))
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        let username = i_user
            .and_then(|i| row.get(i))
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        let password = i_pw.and_then(|i| row.get(i)).unwrap_or_default();
        let notes = i_notes
            .and_then(|i| row.get(i))
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        let folder = i_group
            .and_then(|i| row.get(i))
            .filter(|s| !s.trim().is_empty() && *s != "/")
            .map(|s| s.trim_start_matches('/').to_string());
        // KeePassXC TOTP column may carry either an otpauth:// URI
        // or a raw base32 secret with optional `key=value` tail.
        let totp = i_totp
            .and_then(|i| row.get(i))
            .filter(|s| !s.trim().is_empty())
            .and_then(|s| {
                if s.starts_with("otpauth://") {
                    parse_otpauth_uri(s).ok().map(|(_, cfg)| cfg)
                } else {
                    let synth = format!("otpauth://totp/imported?secret={s}");
                    parse_otpauth_uri(&synth).ok().map(|(_, cfg)| cfg)
                }
            });
        let has_totp = totp.is_some();

        out.push((
            CredentialMetadata {
                format_version: FormatVersion::V1,
                title: title.to_string(),
                url,
                username,
                tags: Vec::new(),
                folder,
                has_totp,
                created_at_ms: 0,
                updated_at_ms: 0,
            },
            CredentialBody {
                format_version: FormatVersion::V1,
                password: SecretString::new(password.to_string()),
                totp,
                notes,
                custom_fields: Vec::new(),
            },
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"
\"Root/Work\",\"GitHub\",\"birkeal\",\"hunter2\",\"https://github.com\",\"my notes\",\"GEZDGNBVGY3TQOJQ\"
\"Root/Personal\",\"Netflix\",\"birkeal\",\"couch_potato\",\"https://netflix.com\",\"\",\"\"
";

    #[test]
    fn parses_two_credentials() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn maps_metadata_fields_with_folder_from_group() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        assert_eq!(creds[0].0.title, "GitHub");
        assert_eq!(creds[0].0.url.as_deref(), Some("https://github.com"));
        assert_eq!(creds[0].0.folder.as_deref(), Some("Root/Work"));
        assert!(creds[0].0.has_totp);
    }

    #[test]
    fn maps_password_into_body() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        assert_eq!(creds[0].1.password.expose_secret(), "hunter2");
    }

    #[test]
    fn missing_title_column_errors_with_helpful_message() {
        let bad = "Group,Username,Password\nRoot,foo,bar\n";
        let err = from_reader(bad.as_bytes()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("Title"));
        assert!(msg.contains("update this parser"));
    }
}
