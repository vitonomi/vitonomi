//! `vitonomi-backup` — passphrase-encrypted credential export.
//!
//! Outer envelope (deterministic CBOR):
//!
//! ```text
//! VitonomiBackup {
//!   magic:          bytes(4) = b"VBK1",
//!   format_version: u8 = 1,
//!   salt:           bytes(16),
//!   argon2_params:  Argon2Params,
//!   nonce:          bytes(24),
//!   ciphertext:     bytes(var),  // AEAD-sealed CBOR(Vec<(Metadata, Body)>)
//! }
//! ```
//!
//! Plaintext is the deterministic-CBOR encoding of the
//! `Vec<(CredentialMetadata, CredentialBody)>` the caller supplied.

use serde::{Deserialize, Serialize};

use crate::crypto::aead::{open as aead_open, seal as aead_seal};
use crate::crypto::argon2::{derive_encryption_key, Argon2Params};
use crate::crypto::random::fill_random;
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::{CryptoError, ProtocolError};

use super::ExportItem;

const MAGIC: &[u8; 4] = b"VBK1";
const FORMAT_VERSION: u8 = 1;
const AAD: &[u8] = b"vitonomi/credential_backup/v1";

#[derive(Serialize, Deserialize)]
struct Envelope {
    #[serde(with = "serde_bytes")]
    magic: Vec<u8>,
    format_version: u8,
    #[serde(with = "serde_bytes")]
    salt: Vec<u8>,
    argon2_params: Argon2Params,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

/// Encrypt `items` under `passphrase` using `params`. Output is
/// the CBOR-encoded envelope.
///
/// # Errors
///
/// Underlying crypto failure.
pub fn encrypt(
    items: &[ExportItem],
    passphrase: &[u8],
    params: Argon2Params,
) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; 16];
    fill_random(&mut salt)?;
    let key = derive_encryption_key(passphrase, &salt, params)?;

    let plaintext = cbor_to_vec(&items.to_vec())
        .map_err(|e| CryptoError::Kdf(format!("backup CBOR encode: {e}")))?;

    let sealed = aead_seal(&key, &plaintext, AAD)?;

    // The seal helper prepends the nonce; split it out for the
    // envelope (and re-attach on decrypt).
    let (nonce, ct) = sealed.split_at(24);

    let env = Envelope {
        magic: MAGIC.to_vec(),
        format_version: FORMAT_VERSION,
        salt: salt.to_vec(),
        argon2_params: params,
        nonce: nonce.to_vec(),
        ciphertext: ct.to_vec(),
    };
    cbor_to_vec(&env).map_err(|e| CryptoError::Kdf(format!("envelope CBOR encode: {e}")))
}

/// Decrypt a `vitonomi-backup` envelope.
///
/// # Errors
///
/// `ProtocolError::Malformed` if the envelope is malformed;
/// `ProtocolError::Cbor` if the inner CBOR fails to decode after
/// decryption (wrong passphrase will surface earlier as an AEAD
/// open error wrapped via `ProtocolError::Malformed`).
pub fn decrypt(
    envelope_bytes: &[u8],
    passphrase: &[u8],
) -> Result<Vec<ExportItem>, ProtocolError> {
    let env: Envelope = cbor_from_slice(envelope_bytes)
        .map_err(|e| ProtocolError::Malformed(format!("backup envelope CBOR: {e}")))?;
    if env.magic != MAGIC {
        return Err(ProtocolError::Malformed(format!(
            "backup magic mismatch: expected {:?}, got {:?}",
            MAGIC, env.magic
        )));
    }
    if env.format_version != FORMAT_VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            got: env.format_version,
            supported: FORMAT_VERSION,
        });
    }
    let key = derive_encryption_key(passphrase, &env.salt, env.argon2_params)
        .map_err(|e| ProtocolError::Malformed(format!("Argon2 derive: {e}")))?;

    let mut sealed = env.nonce.clone();
    sealed.extend_from_slice(&env.ciphertext);
    let plaintext = aead_open(&key, &sealed, AAD)
        .map_err(|e| ProtocolError::Malformed(format!("AEAD open (wrong passphrase?): {e}")))?;

    cbor_from_slice(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::credential::{CredentialBody, CredentialMetadata, SecretString};
    use crate::types::FormatVersion;

    fn fast_params() -> Argon2Params {
        Argon2Params {
            mem_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            out_len: 32,
        }
    }

    fn sample() -> Vec<ExportItem> {
        vec![(
            CredentialMetadata {
                format_version: FormatVersion::V1,
                title: "GitHub".into(),
                url: Some("https://github.com".into()),
                username: Some("birkeal".into()),
                tags: vec!["work".into()],
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
    fn round_trip() {
        let items = sample();
        let bytes = encrypt(&items, b"correct horse battery staple", fast_params()).unwrap();
        let back = decrypt(&bytes, b"correct horse battery staple").unwrap();
        assert_eq!(back, items);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let items = sample();
        let bytes = encrypt(&items, b"good-pw", fast_params()).unwrap();
        assert!(decrypt(&bytes, b"bad-pw").is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let items = sample();
        let mut bytes = encrypt(&items, b"pw", fast_params()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(decrypt(&bytes, b"pw").is_err());
    }

    #[test]
    fn distinct_salts_yield_distinct_ciphertexts() {
        let items = sample();
        let a = encrypt(&items, b"pw", fast_params()).unwrap();
        let b = encrypt(&items, b"pw", fast_params()).unwrap();
        assert_ne!(a, b, "fresh salt + nonce should make ciphertexts differ");
    }
}
