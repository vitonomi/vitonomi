//! Central randomness source. Every other crypto module pulls from
//! here so we have exactly one place to audit + one chokepoint that
//! the encryption-boundary lint can authorise.

use ::getrandom::getrandom;

use crate::errors::CryptoError;

/// Fill `buf` with cryptographically-secure random bytes from the
/// platform RNG.
///
/// # Errors
///
/// Returns `CryptoError::Random` if the platform RNG is unavailable.
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom(buf).map_err(|e| CryptoError::Random(e.to_string()))
}

/// Allocate and return `n` cryptographically-secure random bytes.
///
/// # Errors
///
/// Returns `CryptoError::Random` if the platform RNG is unavailable.
pub fn random_bytes(n: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; n];
    fill_random(&mut buf)?;
    Ok(buf)
}

/// Generate a 32-byte random nonce. Used for challenges, invite
/// nonces, and other places where 256 bits of entropy is the right
/// answer.
///
/// # Errors
///
/// Returns `CryptoError::Random` if the platform RNG is unavailable.
pub fn random_32() -> Result<[u8; 32], CryptoError> {
    let mut out = [0u8; 32];
    fill_random(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_have_correct_length() {
        for n in [0, 1, 16, 32, 1024] {
            assert_eq!(random_bytes(n).unwrap().len(), n);
        }
    }

    #[test]
    fn two_calls_differ() {
        let a = random_32().unwrap();
        let b = random_32().unwrap();
        assert_ne!(
            a, b,
            "two 32-byte randoms collided — extraordinarily unlikely"
        );
    }
}
