//! 1Password CSV importer.
//!
//! Expected header row (columns may appear in any order; missing
//! columns are tolerated by setting the corresponding field to
//! `None` / empty):
//! `Title,Url,Username,Password,OTPAuth,Notes,Tags,Type`
//!
//! TOTP entries appear in the `OTPAuth` column as full
//! `otpauth://...` URIs; we delegate parsing to
//! `core::totp::parse_otpauth_uri`.

use std::io::Read;

use crate::errors::ProtocolError;
use crate::totp::parse_otpauth_uri;
use crate::types::credential::{
    CredentialBody, CredentialMetadata, SecretString,
};
use crate::types::FormatVersion;

use super::ImportedCredential;

/// Parse a 1Password CSV export.
///
/// # Errors
///
/// `ProtocolError::Malformed` if the CSV header does not contain
/// at minimum a `Title` column, or if a row fails to parse.
pub fn from_reader<R: Read>(reader: R) -> Result<Vec<ImportedCredential>, ProtocolError> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);

    let headers = rdr
        .headers()
        .map_err(|e| ProtocolError::Malformed(format!("csv header read: {e}")))?
        .clone();

    let cols = ColIdx::resolve(&headers)?;
    let now_ms = 0u64; // Importer doesn't have a clock; CLI sets created/updated at write time.

    let mut out = Vec::new();
    for (line, row) in rdr.records().enumerate() {
        let row = row.map_err(|e| {
            ProtocolError::Malformed(format!("csv row {} parse: {e}", line + 2))
        })?;
        let title = cols.get(&row, cols.title).unwrap_or_default();
        if title.trim().is_empty() {
            // Skip rows with no title — likely blank trailing row.
            continue;
        }
        let url = cols
            .opt(&row, cols.url)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        let username = cols
            .opt(&row, cols.username)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        let password = cols.opt(&row, cols.password).unwrap_or_default();
        let notes = cols
            .opt(&row, cols.notes)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        let tags = cols
            .opt(&row, cols.tags)
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let totp = cols.opt(&row, cols.otpauth).and_then(|s| {
            if s.trim().is_empty() {
                None
            } else {
                parse_otpauth_uri(s).ok().map(|(_, cfg)| cfg)
            }
        });
        let has_totp = totp.is_some();

        out.push((
            CredentialMetadata {
                format_version: FormatVersion::V1,
                title: title.to_string(),
                url,
                username,
                tags,
                folder: None,
                has_totp,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
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

struct ColIdx {
    title: usize,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    otpauth: Option<usize>,
    notes: Option<usize>,
    tags: Option<usize>,
}

impl ColIdx {
    fn resolve(headers: &csv::StringRecord) -> Result<Self, ProtocolError> {
        let find = |name: &str| -> Option<usize> {
            headers
                .iter()
                .position(|h| h.eq_ignore_ascii_case(name))
        };
        let title = find("Title").ok_or_else(|| {
            ProtocolError::Malformed(
                "1Password CSV missing required `Title` column".into(),
            )
        })?;
        Ok(Self {
            title,
            url: find("Url").or_else(|| find("URL")),
            username: find("Username"),
            password: find("Password"),
            otpauth: find("OTPAuth").or_else(|| find("TOTP")),
            notes: find("Notes"),
            tags: find("Tags"),
        })
    }

    fn get<'a>(&self, row: &'a csv::StringRecord, idx: usize) -> Option<&'a str> {
        row.get(idx)
    }

    fn opt<'a>(&self, row: &'a csv::StringRecord, idx: Option<usize>) -> Option<&'a str> {
        idx.and_then(|i| row.get(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
Title,Url,Username,Password,OTPAuth,Notes,Tags,Type
GitHub,https://github.com,birkeal,hunter2,otpauth://totp/GitHub:birkeal?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30,my notes,work,Login
Netflix,https://netflix.com,birkeal,couch_potato,,kids account,personal,Login
,,,,,,,Header-only row should be skipped if empty
";

    #[test]
    fn parses_two_credentials() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn maps_metadata_fields() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        let (meta, _) = &creds[0];
        assert_eq!(meta.title, "GitHub");
        assert_eq!(meta.url.as_deref(), Some("https://github.com"));
        assert_eq!(meta.username.as_deref(), Some("birkeal"));
        assert_eq!(meta.tags, vec!["work".to_string()]);
        assert!(meta.has_totp);
    }

    #[test]
    fn maps_body_fields() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        let (_, body) = &creds[0];
        assert_eq!(body.password.expose_secret(), "hunter2");
        let totp = body.totp.as_ref().unwrap();
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.period_secs, 30);
    }

    #[test]
    fn no_totp_yields_none_body_and_false_metadata_flag() {
        let creds = from_reader(FIXTURE.as_bytes()).unwrap();
        let (meta, body) = &creds[1];
        assert!(!meta.has_totp);
        assert!(body.totp.is_none());
    }

    #[test]
    fn rejects_csv_without_title_column() {
        let bad = "Url,Username\nhttps://x,foo\n";
        assert!(from_reader(bad.as_bytes()).is_err());
    }
}
