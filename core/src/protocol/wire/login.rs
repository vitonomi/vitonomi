//! Scheme A login wire types (`POST /v1/auth/login/{start,finish}`).

use serde::{Deserialize, Serialize};

use crate::crypto::argon2::Argon2Params;
use crate::crypto::pq::MlDsa65Signature;
use crate::types::{SessionToken, Username};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartRequest {
    pub username: Username,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResponse {
    #[serde(with = "serde_bytes")]
    pub auth_salt: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub enc_salt: Vec<u8>,
    pub argon2_params: Argon2Params,
    /// CBOR-encoded encrypted key blob — see `crate::crypto::keyblob`.
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
