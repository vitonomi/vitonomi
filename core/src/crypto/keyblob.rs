//! Key blob — AEAD-encrypted envelope holding the user's master
//! secret keys. Decrypts under a password-derived encryption key.
//!
//! Per the hub-blindness invariant the hub stores the blob bytes
//! opaquely and MUST NOT carry any auth/Argon2 metadata as
//! separate fields. The blob's plaintext header therefore embeds
//! everything a client needs to redrive the encryption key:
//! `enc_salt` and the `Argon2Params`. The header is bound into the
//! AEAD as associated data so a hub cannot silently downgrade
//! parameters without invalidating the seal.
//!
//! Wire layout (CBOR):
//!
//! ```text
//! KeyBlob {
//!     magic:          [u8; 4]         = b"VKB1",
//!     format_version: u8              = 1,
//!     enc_salt:       Vec<u8>         (>= 16 bytes random),
//!     argon2_params:  Argon2Params,
//!     ciphertext:     Vec<u8>,        // nonce(24) || aead_ct(MasterSecretKeys-CBOR)
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::crypto::aead::{open, seal, AeadKey};
use crate::crypto::argon2::{derive_encryption_key, Argon2Params};
use crate::crypto::keys::MasterSecretKeys;
use crate::crypto::random::random_bytes;
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::CryptoError;

/// Magic bytes identifying a vitonomi key blob.
pub const MAGIC: [u8; 4] = *b"VKB1";

/// Current key-blob format version.
pub const FORMAT_VERSION: u8 = 1;

/// Default `enc_salt` length in bytes. Argon2 spec recommends at
/// least 16; we use exactly 16.
pub const SALT_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBlob {
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    pub format_version: u8,
    #[serde(with = "serde_bytes")]
    pub enc_salt: Vec<u8>,
    pub argon2_params: Argon2Params,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Plaintext header of a key blob — everything a client needs to
/// derive the encryption key from a password before unsealing the
/// inner secrets. Returned by [`parse_header`] for the login path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlobHeader {
    pub format_version: u8,
    pub enc_salt: Vec<u8>,
    pub argon2_params: Argon2Params,
}

/// Encrypt `secrets` under a password-derived AEAD key. Generates
/// a fresh random `enc_salt`. Returns the CBOR-serialised envelope
/// ready to ship to the hub.
///
/// # Errors
///
/// Crypto / RNG / serialisation failures.
pub fn encrypt_with_password(
    password: &[u8],
    params: Argon2Params,
    secrets: &MasterSecretKeys,
) -> Result<Vec<u8>, CryptoError> {
    let salt = random_bytes(SALT_LEN)?;
    encrypt_with_password_and_salt(password, &salt, params, secrets)
}

/// Encrypt with an explicit salt — used by tests for determinism.
///
/// # Errors
///
/// Same as [`encrypt_with_password`].
pub fn encrypt_with_password_and_salt(
    password: &[u8],
    enc_salt: &[u8],
    params: Argon2Params,
    secrets: &MasterSecretKeys,
) -> Result<Vec<u8>, CryptoError> {
    let key = derive_encryption_key(password, enc_salt, params)?;
    encrypt_with_key(&key, enc_salt, params, secrets)
}

/// Encrypt with an already-derived AEAD key. The header is built
/// from the supplied `enc_salt` + `params` so a future
/// [`decrypt_with_password`] can re-derive the same key.
///
/// # Errors
///
/// AEAD / serialisation failures.
pub fn encrypt_with_key(
    key: &AeadKey,
    enc_salt: &[u8],
    params: Argon2Params,
    secrets: &MasterSecretKeys,
) -> Result<Vec<u8>, CryptoError> {
    let pt = cbor_to_vec(secrets).map_err(|e| CryptoError::KeyBlob(format!("CBOR: {e}")))?;
    let aad = aad_bytes(enc_salt, params);
    let ct = seal(key, &pt, &aad)?;
    let blob = KeyBlob {
        magic: MAGIC.to_vec(),
        format_version: FORMAT_VERSION,
        enc_salt: enc_salt.to_vec(),
        argon2_params: params,
        ciphertext: ct,
    };
    cbor_to_vec(&blob).map_err(|e| CryptoError::KeyBlob(format!("CBOR: {e}")))
}

/// Parse the plaintext header without unsealing — used at login
/// time so the client knows which Argon2 params + salt to apply
/// to the password.
///
/// # Errors
///
/// `CryptoError::KeyBlob` on malformed envelope.
pub fn parse_header(encoded: &[u8]) -> Result<KeyBlobHeader, CryptoError> {
    let blob: KeyBlob =
        cbor_from_slice(encoded).map_err(|e| CryptoError::KeyBlob(format!("CBOR: {e}")))?;
    if blob.magic != MAGIC {
        return Err(CryptoError::KeyBlob("bad magic".into()));
    }
    if blob.format_version != FORMAT_VERSION {
        return Err(CryptoError::KeyBlob(format!(
            "unsupported format_version {}",
            blob.format_version
        )));
    }
    Ok(KeyBlobHeader {
        format_version: blob.format_version,
        enc_salt: blob.enc_salt,
        argon2_params: blob.argon2_params,
    })
}

/// Decrypt a blob using the password the user just typed.
///
/// # Errors
///
/// `CryptoError::AeadOpen` on wrong password or tampered bytes.
pub fn decrypt_with_password(
    password: &[u8],
    encoded: &[u8],
) -> Result<MasterSecretKeys, CryptoError> {
    let blob: KeyBlob =
        cbor_from_slice(encoded).map_err(|e| CryptoError::KeyBlob(format!("CBOR: {e}")))?;
    if blob.magic != MAGIC {
        return Err(CryptoError::KeyBlob("bad magic".into()));
    }
    if blob.format_version != FORMAT_VERSION {
        return Err(CryptoError::KeyBlob(format!(
            "unsupported format_version {}",
            blob.format_version
        )));
    }
    let key = derive_encryption_key(password, &blob.enc_salt, blob.argon2_params)?;
    let aad = aad_bytes(&blob.enc_salt, blob.argon2_params);
    let pt = open(&key, &blob.ciphertext, &aad)?;
    let secrets: MasterSecretKeys =
        cbor_from_slice(&pt).map_err(|e| CryptoError::KeyBlob(format!("inner CBOR: {e}")))?;
    Ok(secrets)
}

/// Lower-level decrypt with an already-derived AEAD key. Used by
/// callers that decoupled key derivation (e.g. for caching).
///
/// # Errors
///
/// `CryptoError::AeadOpen` on wrong key or tampered bytes.
pub fn decrypt_with_key(key: &AeadKey, encoded: &[u8]) -> Result<MasterSecretKeys, CryptoError> {
    let blob: KeyBlob =
        cbor_from_slice(encoded).map_err(|e| CryptoError::KeyBlob(format!("CBOR: {e}")))?;
    if blob.magic != MAGIC {
        return Err(CryptoError::KeyBlob("bad magic".into()));
    }
    if blob.format_version != FORMAT_VERSION {
        return Err(CryptoError::KeyBlob(format!(
            "unsupported format_version {}",
            blob.format_version
        )));
    }
    let aad = aad_bytes(&blob.enc_salt, blob.argon2_params);
    let pt = open(key, &blob.ciphertext, &aad)?;
    let secrets: MasterSecretKeys =
        cbor_from_slice(&pt).map_err(|e| CryptoError::KeyBlob(format!("inner CBOR: {e}")))?;
    Ok(secrets)
}

fn aad_bytes(enc_salt: &[u8], params: Argon2Params) -> Vec<u8> {
    // Bind every plaintext header field into the AEAD AAD so a
    // tampered hub cannot silently downgrade salt or Argon2
    // parameters without invalidating the seal.
    let params_bytes = cbor_to_vec(&params).expect("Argon2Params CBOR serialise cannot fail");
    let mut aad = Vec::with_capacity(MAGIC.len() + 1 + enc_salt.len() + params_bytes.len());
    aad.extend_from_slice(&MAGIC);
    aad.push(FORMAT_VERSION);
    aad.extend_from_slice(enc_salt);
    aad.extend_from_slice(&params_bytes);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::MasterKeys;

    fn fast_params() -> Argon2Params {
        Argon2Params {
            mem_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            out_len: 32,
        }
    }

    #[test]
    fn round_trip_with_password() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let blob = encrypt_with_password(b"correct horse", fast_params(), &secrets).unwrap();
        let recovered = decrypt_with_password(b"correct horse", &blob).unwrap();
        assert_eq!(recovered.identity.0, secrets.identity.0);
        assert_eq!(recovered.cluster_admin.0, secrets.cluster_admin.0);
        assert_eq!(recovered.kem.0, secrets.kem.0);
    }

    #[test]
    fn wrong_password_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let blob = encrypt_with_password(b"correct", fast_params(), &secrets).unwrap();
        assert!(matches!(
            decrypt_with_password(b"wrong", &blob),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn header_parses_without_password() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let salt = vec![0xa5u8; 16];
        let blob = encrypt_with_password_and_salt(b"pw", &salt, fast_params(), &secrets).unwrap();
        let header = parse_header(&blob).unwrap();
        assert_eq!(header.format_version, FORMAT_VERSION);
        assert_eq!(header.enc_salt, salt);
        assert_eq!(header.argon2_params, fast_params());
    }

    #[test]
    fn bad_magic_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let blob = encrypt_with_password(b"pw", fast_params(), &secrets).unwrap();
        let mut tampered: KeyBlob = cbor_from_slice(&blob).unwrap();
        tampered.magic = b"XXXX".to_vec();
        let encoded = cbor_to_vec(&tampered).unwrap();
        assert!(matches!(
            decrypt_with_password(b"pw", &encoded),
            Err(CryptoError::KeyBlob(_))
        ));
    }

    #[test]
    fn version_mismatch_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let blob = encrypt_with_password(b"pw", fast_params(), &secrets).unwrap();
        let mut tampered: KeyBlob = cbor_from_slice(&blob).unwrap();
        tampered.format_version = 99;
        let encoded = cbor_to_vec(&tampered).unwrap();
        assert!(matches!(
            decrypt_with_password(b"pw", &encoded),
            Err(CryptoError::KeyBlob(_))
        ));
    }

    #[test]
    fn tampered_salt_rejected() {
        // A hub that swaps out the enc_salt to one it knows would
        // make the AAD-bound seal fail to open.
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let blob = encrypt_with_password(b"pw", fast_params(), &secrets).unwrap();
        let mut tampered: KeyBlob = cbor_from_slice(&blob).unwrap();
        tampered.enc_salt[0] ^= 0x01;
        let encoded = cbor_to_vec(&tampered).unwrap();
        assert!(matches!(
            decrypt_with_password(b"pw", &encoded),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn tampered_params_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let blob = encrypt_with_password(b"pw", fast_params(), &secrets).unwrap();
        let mut tampered: KeyBlob = cbor_from_slice(&blob).unwrap();
        tampered.argon2_params.time_cost += 1;
        let encoded = cbor_to_vec(&tampered).unwrap();
        assert!(matches!(
            decrypt_with_password(b"pw", &encoded),
            Err(CryptoError::AeadOpen)
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let blob = encrypt_with_password(b"pw", fast_params(), &secrets).unwrap();
        let mut tampered: KeyBlob = cbor_from_slice(&blob).unwrap();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 0x01;
        let encoded = cbor_to_vec(&tampered).unwrap();
        assert!(matches!(
            decrypt_with_password(b"pw", &encoded),
            Err(CryptoError::AeadOpen)
        ));
    }
}
