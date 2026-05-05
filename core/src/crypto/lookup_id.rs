//! `user_lookup_id` derivation. Replaces `username` on the wire so the
//! hub never sees the raw user identifier.
//!
//! `lookup_id = argon2id(username || cluster_pepper, salt=cluster_id,
//! m=32 MiB, t=2, p=1, out_len=32)`. The pepper makes the function
//! impossible to invert without access to the user's encrypted key
//! blob (which holds the pepper).

use argon2::{Algorithm, Argon2, Params, Version};

use crate::crypto::cluster_keys::ClusterPepper;
use crate::errors::CryptoError;
use crate::types::{ClusterId, Username};

/// Argon2id parameters used for the `lookup_id` derivation. These are
/// distinct from the parameters used for the encryption key (which are
/// stored per-user in the key blob header).
#[derive(Debug, Clone, Copy)]
pub struct LookupIdParams {
    pub mem_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl LookupIdParams {
    /// Production defaults: 32 MiB / t=2 / p=1.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            mem_kib: 32 * 1024,
            time_cost: 2,
            parallelism: 1,
        }
    }

    /// Fast test profile.
    #[cfg(feature = "test-crypto")]
    #[must_use]
    pub const fn test_fast() -> Self {
        Self {
            mem_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
        }
    }

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
}

/// Length of a `user_lookup_id` (32 bytes, base64url-encoded on the
/// wire).
pub const LOOKUP_ID_LEN: usize = 32;

/// Compute `user_lookup_id`.
///
/// # Errors
///
/// Returns `CryptoError::Kdf` on Argon2 parameter / hash failure.
pub fn compute_lookup_id(
    username: &Username,
    cluster_pepper: &ClusterPepper,
    cluster_id: &ClusterId,
    params: LookupIdParams,
) -> Result<[u8; LOOKUP_ID_LEN], CryptoError> {
    let p = Params::new(
        params.mem_kib,
        params.time_cost,
        params.parallelism,
        Some(LOOKUP_ID_LEN),
    )
    .map_err(|e| CryptoError::Kdf(format!("lookup_id params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut password =
        Vec::with_capacity(username.as_str().len() + cluster_pepper.as_bytes().len());
    password.extend_from_slice(username.as_str().as_bytes());
    password.extend_from_slice(cluster_pepper.as_bytes());

    let mut out = [0u8; LOOKUP_ID_LEN];
    argon
        .hash_password_into(&password, cluster_id.as_bytes(), &mut out)
        .map_err(|e| CryptoError::Kdf(format!("lookup_id hash: {e}")))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cluster_keys::derive_cluster_pepper;
    use crate::crypto::seedphrase::SeedPhrase;

    fn fast() -> LookupIdParams {
        LookupIdParams {
            mem_kib: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn fixture() -> (Username, ClusterPepper, ClusterId) {
        let phrase = SeedPhrase::generate().unwrap();
        let pepper = derive_cluster_pepper(&phrase.to_seed(""));
        let cid = ClusterId([7u8; 32]);
        (Username::parse("birkeal").unwrap(), pepper, cid)
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let (u, p, c) = fixture();
        let a = compute_lookup_id(&u, &p, &c, fast()).unwrap();
        let b = compute_lookup_id(&u, &p, &c, fast()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_usernames_diverge() {
        let (_, p, c) = fixture();
        let u1 = Username::parse("birkeal").unwrap();
        let u2 = Username::parse("ghost").unwrap();
        assert_ne!(
            compute_lookup_id(&u1, &p, &c, fast()).unwrap(),
            compute_lookup_id(&u2, &p, &c, fast()).unwrap(),
        );
    }

    #[test]
    fn different_peppers_diverge() {
        let (u, _, c) = fixture();
        let p1 = ClusterPepper(vec![1u8; 32]);
        let p2 = ClusterPepper(vec![2u8; 32]);
        assert_ne!(
            compute_lookup_id(&u, &p1, &c, fast()).unwrap(),
            compute_lookup_id(&u, &p2, &c, fast()).unwrap(),
        );
    }

    #[test]
    fn different_cluster_ids_diverge() {
        let (u, p, _) = fixture();
        let c1 = ClusterId([1u8; 32]);
        let c2 = ClusterId([2u8; 32]);
        assert_ne!(
            compute_lookup_id(&u, &p, &c1, fast()).unwrap(),
            compute_lookup_id(&u, &p, &c2, fast()).unwrap(),
        );
    }
}
