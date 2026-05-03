//! BIP-39 24-word seed phrase. English wordlist pinned. The seed
//! bytes feed into [`crate::crypto::keys`] which derives the
//! ML-DSA-65 / ML-KEM-768 keypairs via HKDF-SHA-256.

use bip39::{Language, Mnemonic};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::random::random_bytes;
use crate::errors::CryptoError;

/// 32 bytes of entropy → BIP-39 24 words.
pub const ENTROPY_BYTES: usize = 32;
/// 64-byte seed produced by BIP-39 PBKDF2 (we use it as
/// HKDF-SHA-256 master input).
pub const SEED_BYTES: usize = 64;

/// 24-word BIP-39 mnemonic. Wraps the upstream type to keep the
/// `bip39` dep a `core`-only concern.
#[derive(Clone)]
pub struct SeedPhrase {
    mnemonic: Mnemonic,
}

impl SeedPhrase {
    /// Generate a fresh 24-word seed phrase.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Random` on RNG failure or
    /// `CryptoError::SeedPhrase` if the entropy bytes are rejected
    /// by the upstream library.
    pub fn generate() -> Result<Self, CryptoError> {
        let entropy = random_bytes(ENTROPY_BYTES)?;
        Self::from_entropy(&entropy)
    }

    /// Build a phrase from 32 bytes of entropy.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SeedPhrase` on malformed entropy.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, CryptoError> {
        if entropy.len() != ENTROPY_BYTES {
            return Err(CryptoError::SeedPhrase(format!(
                "entropy must be {ENTROPY_BYTES} bytes, got {}",
                entropy.len()
            )));
        }
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
            .map_err(|e| CryptoError::SeedPhrase(e.to_string()))?;
        Ok(Self { mnemonic })
    }

    /// Parse and validate a phrase string. Trims surrounding
    /// whitespace; the upstream library handles checksum + word
    /// validity.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SeedPhrase` on invalid input.
    pub fn parse(phrase: &str) -> Result<Self, CryptoError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase.trim())
            .map_err(|e| CryptoError::SeedPhrase(e.to_string()))?;
        let words = mnemonic.word_count();
        if words != 24 {
            return Err(CryptoError::SeedPhrase(format!(
                "vitonomi requires 24-word phrases, got {words}"
            )));
        }
        Ok(Self { mnemonic })
    }

    /// The phrase as a space-separated word string. Returned bytes
    /// are zeroised by the caller (the wrapper keeps lifetime safe).
    #[must_use]
    pub fn to_words(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Derive the BIP-39 64-byte seed using PBKDF2 with the supplied
    /// passphrase ("" for none — vitonomi recommends none and
    /// derives further keys via Argon2id on the password instead).
    #[must_use]
    pub fn to_seed(&self, passphrase: &str) -> SeedBytes {
        SeedBytes(self.mnemonic.to_seed(passphrase))
    }

    /// The raw 32-byte entropy backing this mnemonic.
    #[must_use]
    pub fn to_entropy(&self) -> SeedEntropy {
        let v = self.mnemonic.to_entropy();
        let mut buf = [0u8; ENTROPY_BYTES];
        let n = ENTROPY_BYTES.min(v.len());
        buf[..n].copy_from_slice(&v[..n]);
        SeedEntropy(buf)
    }
}

/// 32-byte entropy backing a [`SeedPhrase`]. Zeroised on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SeedEntropy(pub [u8; ENTROPY_BYTES]);

impl SeedEntropy {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ENTROPY_BYTES] {
        &self.0
    }
}

/// 64-byte BIP-39 seed (PBKDF2-derived). Zeroised on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SeedBytes(pub [u8; SEED_BYTES]);

impl SeedBytes {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SEED_BYTES] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_24_words() {
        let phrase = SeedPhrase::generate().unwrap();
        assert_eq!(phrase.to_words().split_whitespace().count(), 24);
    }

    #[test]
    fn round_trip_via_string() {
        let phrase = SeedPhrase::generate().unwrap();
        let s = phrase.to_words();
        let back = SeedPhrase::parse(&s).unwrap();
        assert_eq!(back.to_words(), s);
    }

    #[test]
    fn round_trip_via_entropy() {
        let phrase = SeedPhrase::generate().unwrap();
        let entropy = phrase.to_entropy();
        let back = SeedPhrase::from_entropy(entropy.as_bytes()).unwrap();
        assert_eq!(phrase.to_words(), back.to_words());
    }

    #[test]
    fn rejects_short_phrase() {
        // 12-word phrase
        let p = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(matches!(
            SeedPhrase::parse(p),
            Err(CryptoError::SeedPhrase(_))
        ));
    }

    #[test]
    fn rejects_bad_checksum() {
        // 24 valid words but with a bad checksum.
        let p = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(matches!(
            SeedPhrase::parse(p),
            Err(CryptoError::SeedPhrase(_))
        ));
    }

    #[test]
    fn rejects_garbage_word() {
        let p = "asdf qwerty zzz xxx yyy abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(matches!(
            SeedPhrase::parse(p),
            Err(CryptoError::SeedPhrase(_))
        ));
    }

    #[test]
    fn rejects_wrong_entropy_length() {
        assert!(matches!(
            SeedPhrase::from_entropy(&[0u8; 16]),
            Err(CryptoError::SeedPhrase(_))
        ));
        assert!(matches!(
            SeedPhrase::from_entropy(&[0u8; 31]),
            Err(CryptoError::SeedPhrase(_))
        ));
    }

    #[test]
    fn seed_bytes_deterministic() {
        let entropy = [0x42u8; ENTROPY_BYTES];
        let phrase = SeedPhrase::from_entropy(&entropy).unwrap();
        let a = phrase.to_seed("");
        let b = phrase.to_seed("");
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
