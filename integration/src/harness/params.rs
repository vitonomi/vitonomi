//! Shared Argon2id parameter profiles + dummy fingerprint used by
//! the harness. Production profiles are too slow for CI; tests use
//! the deliberately-cheap `m=8 MiB / t=1` profile from the
//! `test-crypto` feature.

use vitonomi_core::crypto::argon2::Argon2Params;
use vitonomi_core::crypto::lookup_id::LookupIdParams;

/// Argon2id parameters used to wrap the test admin's key blob.
/// Cheap enough to run on CI; not for production use.
#[must_use]
pub fn fast_keyblob_params() -> Argon2Params {
    Argon2Params {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
        out_len: 32,
    }
}

/// Argon2id parameters used to derive the test admin's
/// `user_lookup_id`. Same cheap profile.
#[must_use]
pub fn fast_lookup_params() -> LookupIdParams {
    LookupIdParams {
        mem_kib: 8 * 1024,
        time_cost: 1,
        parallelism: 1,
    }
}

/// 32 zero bytes encoded as the SPKI fingerprint. The hub speaks
/// http:// in tests so the SPKI verifier is constructed but never
/// invoked; the bytes never need to match a real cert.
#[must_use]
pub fn dummy_fingerprint() -> String {
    "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()
}
