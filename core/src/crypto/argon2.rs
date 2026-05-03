//! Argon2id KDF. Single derivation: password + salt + parameters →
//! 32-byte encryption key. Scheme A login (per the mini-MVP plan)
//! never sends an `auth_key` to the server, so this module only
//! exposes the encryption-key derivation; the verifier-style flow
//! is intentionally absent.

use ::argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::aead::AeadKey;
use crate::errors::CryptoError;

/// Tunable Argon2id parameters. Production: m≥256 MiB, t=3, p=1.
/// Tests use a low-memory profile via the `test-crypto` feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost (KiB).
    pub mem_kib: u32,
    /// Iteration count.
    pub time_cost: u32,
    /// Parallelism degree.
    pub parallelism: u32,
    /// Output length in bytes.
    pub out_len: u32,
}

impl Argon2Params {
    /// Production defaults: 256 MiB memory, 3 iterations, 1 lane,
    /// 32-byte output.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            mem_kib: 256 * 1024,
            time_cost: 3,
            parallelism: 1,
            out_len: 32,
        }
    }

    /// Fast test defaults — only available with the `test-crypto`
    /// feature flag.
    #[cfg(feature = "test-crypto")]
    #[must_use]
    pub const fn test_fast() -> Self {
        Self {
            mem_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            out_len: 32,
        }
    }

    /// Default parameter set: production unless the `test-crypto`
    /// feature is on.
    #[must_use]
    pub fn default_for_env() -> Self {
        #[cfg(feature = "test-crypto")]
        {
            Self::test_fast()
        }
        #[cfg(not(feature = "test-crypto"))]
        {
            Self::production()
        }
    }

    /// Returns true iff these parameters are at least as strong as the
    /// production minimum (m≥256 MiB, t≥3, p≥1).
    #[must_use]
    pub const fn meets_production_minimum(&self) -> bool {
        self.mem_kib >= 256 * 1024 && self.time_cost >= 3 && self.parallelism >= 1
    }
}

/// Derive a 256-bit encryption key from `password` + `salt` using
/// Argon2id with the supplied parameters.
///
/// # Errors
///
/// Returns `CryptoError::Kdf` on malformed parameters or hash failure.
pub fn derive_encryption_key(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<AeadKey, CryptoError> {
    if params.out_len != 32 {
        return Err(CryptoError::Kdf("encryption key must be 32 bytes".into()));
    }
    let p = Params::new(
        params.mem_kib,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::Kdf(format!("Argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| CryptoError::Kdf(format!("Argon2 hash: {e}")))?;

    let key = AeadKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead::{open, seal};

    fn fast_params() -> Argon2Params {
        // Tests always use a fast profile regardless of feature flag.
        Argon2Params {
            mem_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
            out_len: 32,
        }
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let p = fast_params();
        let salt = b"sixteen-byte-saltzz";
        let a = derive_encryption_key(b"correct horse battery staple", salt, p).unwrap();
        let b = derive_encryption_key(b"correct horse battery staple", salt, p).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_passwords_give_different_keys() {
        let p = fast_params();
        let salt = b"sixteen-byte-saltzz";
        let a = derive_encryption_key(b"password-one", salt, p).unwrap();
        let b = derive_encryption_key(b"password-two", salt, p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salts_give_different_keys() {
        let p = fast_params();
        let a = derive_encryption_key(b"pw", b"salt-aaaaaaaaaaaa", p).unwrap();
        let b = derive_encryption_key(b"pw", b"salt-bbbbbbbbbbbb", p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derived_key_works_for_aead() {
        let p = fast_params();
        let key = derive_encryption_key(b"secret", b"sixteen-byte-saltzz", p).unwrap();
        let ct = seal(&key, b"hello", b"ad").unwrap();
        assert_eq!(open(&key, &ct, b"ad").unwrap(), b"hello");
    }

    #[test]
    fn production_minimum_check() {
        assert!(Argon2Params::production().meets_production_minimum());
        assert!(!fast_params().meets_production_minimum());
    }
}
