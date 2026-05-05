//! Scheme A login wire types (`POST /v1/auth/login/{start,finish}`).
//!
//! Hub-blind: the client sends a `lookup_id` (32-byte Argon2id-derived
//! opaque value) — never the raw username.

use serde::{Deserialize, Serialize};

use crate::crypto::pq::MlDsa65Signature;
use crate::types::SessionToken;

/// 32-byte opaque lookup id. Output of
/// [`crate::crypto::lookup_id::compute_lookup_id`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserLookupId(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl UserLookupId {
    pub const LEN: usize = 32;

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartRequest {
    pub lookup_id: UserLookupId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// Opaque key blob — its plaintext header carries auth_salt,
    /// enc_salt, and Argon2id parameters. The client parses the
    /// header without needing the password; the inner ciphertext
    /// requires the password-derived encryption key to open.
    #[serde(with = "serde_bytes")]
    pub encrypted_key_blob: Vec<u8>,
    pub challenge: crate::crypto::challenge::Challenge,
    pub challenge_id: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    pub challenge_id: String,
    pub signature: MlDsa65Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    pub session_token: SessionToken,
    pub session_expires_at_ms: u64,
}
