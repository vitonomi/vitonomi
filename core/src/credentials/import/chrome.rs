//! Chrome / Chromium password CSV importer.
//!
//! Expected header row in current Chromium builds:
//! `name,url,username,password,note`
//!
//! Older Chrome exports omit the `note` column; we tolerate that.
//! Chrome stores no TOTP / tags / folder data, so the resulting
//! `CredentialMetadata` has those fields empty.

use std::io::Read;

use crate::errors::ProtocolError;
use crate::types::credential::{
    CredentialBody, CredentialMetadata, SecretString,
};
use crate::types::FormatVersion;

use super::ImportedCredential;

/// Parse a Chrome / Chromium password CSV export.
///
/// # Errors
///
/// `ProtocolError::Malformed` if the header is missing the
/// minimum `name,url,username,password` columns or a row fails
/// to parse.
pub fn from_reader<R: Read>(reader: R) -> Result<Vec<ImportedCredential>, ProtocolError> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);

    let headers = rdr
        .headers()
        .map_err(|e| ProtocolError::Malformed(format!("csv header read: {e}")))?
        .clone();

    let find = |label: &str| -> Option<usize> {
        headers.iter().position(|h| h.eq_ignore_ascii_case(label))
    };
    let i_name = find("name").ok_or_else(|| {
        ProtocolError::Malformed(
            "Chrome CSV missing required `name` column — header was: \
             expected name,url,username,password[,note]"
                .into(),
        )
    })?;
    let i_url = find("url");
    let i_user = find("username");
    let i_pw = find("password");
    let i_note = find("note");

    let mut out = Vec::new();
    for (line, row) in rdr.records().enumerate() {
        let row = row.map_err(|e| {
            ProtocolError::Malformed(format!("csv row {} parse: {e}", line + 2))
        })?;
        let title = row.get(i_name).unwrap_or_default();
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
        let notes = i_note
            .and_then(|i| row.get(i))
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);

        out.push((
            CredentialMetadata {
                format_version: FormatVersion::V1,
                title: title.to_string(),
                url,
                username,
                tags: Vec::new(),
                folder: None,
                has_totp: false,
                created_at_ms: 0,
                updated_at_ms: 0,
            },
            CredentialBody {
                format_version: FormatVersion::V1,
                password: SecretString::new(password.to_string()),
                totp: None,
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
name,url,username,password,note
GitHub,https://github.com,birkeal,hunter2,my notes
Netflix,https://netflix.com,birkeal,couch_potato,
";

    #[test]
    fn parses_two_credentials() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].0.title, "GitHub");
        assert_eq!(creds[1].0.title, "Netflix");
        assert_eq!(creds[0].1.password.expose_secret(), "hunter2");
    }

    #[test]
    fn tolerates_missing_note_column() {
        let csv = "name,url,username,password\nGitHub,https://github.com,birkeal,hunter2\n";
        let creds = from_reader(csv.as_bytes()).unwrap();
        assert_eq!(creds.len(), 1);
        assert!(creds[0].1.notes.is_none());
    }

    #[test]
    fn rejects_csv_without_name_column() {
        let bad = "url,username,password\nhttps://x,foo,bar\n";
        assert!(from_reader(bad.as_bytes()).is_err());
    }
}
