//! Plaintext-JSON credential export. **Unsafe**: every secret is
//! revealed.
//!
//! Gated behind a `force_plain` boolean the CLI must set only
//! after a confirm-twice prompt.

use crate::errors::ProtocolError;

use super::ExportItem;

/// Serialize `items` to a pretty-printed JSON Vec.
///
/// # Errors
///
/// `ProtocolError::Malformed` if `force_plain` is `false`.
/// `ProtocolError::Cbor` (mis-named — covers any serde_json error)
/// if the JSON encoder fails (unreachable for well-typed inputs).
pub fn export_json(items: &[ExportItem], force_plain: bool) -> Result<String, ProtocolError> {
    if !force_plain {
        return Err(ProtocolError::Malformed(
            "plaintext-JSON export refused without `force_plain = true`; \
             this serializes every password and TOTP secret in the clear"
                .into(),
        ));
    }
    serde_json::to_string_pretty(items).map_err(|e| ProtocolError::Cbor(format!("json encode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::credential::{CredentialBody, CredentialMetadata, SecretString};
    use crate::types::FormatVersion;

    fn sample() -> Vec<ExportItem> {
        vec![(
            CredentialMetadata {
                format_version: FormatVersion::V1,
                title: "GitHub".into(),
                url: None,
                username: None,
                tags: Vec::new(),
                folder: None,
                has_totp: false,
                created_at_ms: 0,
                updated_at_ms: 0,
            },
            CredentialBody {
                format_version: FormatVersion::V1,
                password: SecretString::new("hunter2".into()),
                totp: None,
                notes: None,
                custom_fields: Vec::new(),
            },
        )]
    }

    #[test]
    fn refuses_without_force_plain() {
        let items = sample();
        assert!(export_json(&items, false).is_err());
    }

    #[test]
    fn allows_with_force_plain() {
        let items = sample();
        let s = export_json(&items, true).unwrap();
        assert!(s.contains("GitHub"));
        assert!(s.contains("hunter2"));
    }
}
