//! Key blob — AEAD-encrypted envelope holding the user's master
//! secret keys. Decrypts under the password-derived encryption key
//! ([`crate::crypto::argon2::derive_encryption_key`]).
//!
//! Wire layout (CBOR):
//!
//! ```text
//! KeyBlob {
//!     magic: [u8; 4]        = b"VKB1",
//!     format_version: u8    = 1,
//!     ciphertext: Vec<u8>,  // nonce || aead_ct(MasterSecretKeys-CBOR)
//! }
//! ```
//!
//! AEAD: XChaCha20-Poly1305, AAD = `magic || format_version`.

use serde::{Deserialize, Serialize};

use crate::crypto::aead::{open, seal, AeadKey};
use crate::crypto::keys::MasterSecretKeys;
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::CryptoError;

/// Magic bytes identifying a vitonomi key blob.
pub const MAGIC: [u8; 4] = *b"VKB1";

/// Current key-blob format version.
pub const FORMAT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBlob {
    #[serde(with = "serde_bytes")]
    pub magic: Vec<u8>,
    pub format_version: u8,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Encrypt `secrets` under `key`. Returns the CBOR-serialised
/// envelope ready to persist.
///
/// # Errors
///
/// Returns `CryptoError::AeadSeal` on AEAD failure or
/// `CryptoError::KeyBlob` on serialisation failure.
pub fn encrypt(key: &AeadKey, secrets: &MasterSecretKeys) -> Result<Vec<u8>, CryptoError> {
    let pt = cbor_to_vec(secrets).map_err(|e| CryptoError::KeyBlob(format!("CBOR: {e}")))?;
    let aad = aad_bytes();
    let ct = seal(key, &pt, &aad)?;
    let blob = KeyBlob {
        magic: MAGIC.to_vec(),
        format_version: FORMAT_VERSION,
        ciphertext: ct,
    };
    cbor_to_vec(&blob).map_err(|e| CryptoError::KeyBlob(format!("CBOR: {e}")))
}

/// Decrypt a key blob.
///
/// # Errors
///
/// Returns `CryptoError::KeyBlob` on malformed envelope or
/// `CryptoError::AeadOpen` on AEAD failure (wrong key or tampering).
pub fn decrypt(key: &AeadKey, encoded: &[u8]) -> Result<MasterSecretKeys, CryptoError> {
    let blob: KeyBlob =
        cbor_from_slice(encoded).map_err(|e| CryptoError::KeyBlob(format!("CBOR: {e}")))?;

    if blob.magic != MAGIC {
        return Err(CryptoError::KeyBlob("bad magic".into()));
    }
    if blob.format_version != FORMAT_VERSION {
        return Err(CryptoError::KeyBlob(format!(
            "unsupported format_version {got}",
            got = blob.format_version
        )));
    }

    let aad = aad_bytes();
    let pt = open(key, &blob.ciphertext, &aad)?;
    let secrets: MasterSecretKeys =
        cbor_from_slice(&pt).map_err(|e| CryptoError::KeyBlob(format!("inner CBOR: {e}")))?;
    Ok(secrets)
}

fn aad_bytes() -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + 1);
    aad.extend_from_slice(&MAGIC);
    aad.push(FORMAT_VERSION);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::MasterKeys;

    fn key() -> AeadKey {
        AeadKey::from_bytes([9u8; 32])
    }

    #[test]
    fn round_trip() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);

        let blob = encrypt(&key(), &secrets).unwrap();
        let recovered = decrypt(&key(), &blob).unwrap();

        assert_eq!(recovered.identity.0, secrets.identity.0);
        assert_eq!(recovered.cluster_admin.0, secrets.cluster_admin.0);
        assert_eq!(recovered.kem.0, secrets.kem.0);
    }

    #[test]
    fn wrong_key_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let secrets = MasterSecretKeys::from_keypair(&mk);
        let blob = encrypt(&key(), &secrets).unwrap();
        let bad = AeadKey::from_bytes([0u8; 32]);
        assert!(matches!(decrypt(&bad, &blob), Err(CryptoError::AeadOpen)));
    }

    #[test]
    fn bad_magic_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let blob = encrypt(&key(), &MasterSecretKeys::from_keypair(&mk)).unwrap();
        let mut tampered: KeyBlob = cbor_from_slice(&blob).unwrap();
        tampered.magic = b"XXXX".to_vec();
        let encoded = cbor_to_vec(&tampered).unwrap();
        assert!(matches!(
            decrypt(&key(), &encoded),
            Err(CryptoError::KeyBlob(_))
        ));
    }

    #[test]
    fn version_mismatch_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let blob = encrypt(&key(), &MasterSecretKeys::from_keypair(&mk)).unwrap();
        let mut tampered: KeyBlob = cbor_from_slice(&blob).unwrap();
        tampered.format_version = 99;
        let encoded = cbor_to_vec(&tampered).unwrap();
        assert!(matches!(
            decrypt(&key(), &encoded),
            Err(CryptoError::KeyBlob(_))
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mk = MasterKeys::generate().unwrap();
        let blob = encrypt(&key(), &MasterSecretKeys::from_keypair(&mk)).unwrap();
        let mut tampered: KeyBlob = cbor_from_slice(&blob).unwrap();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 0x01;
        let encoded = cbor_to_vec(&tampered).unwrap();
        assert!(matches!(
            decrypt(&key(), &encoded),
            Err(CryptoError::AeadOpen)
        ));
    }
}
