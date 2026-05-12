//! Public user-pubkey lookup. Pubkeys are public material — no auth.
//!
//! Used by vaults to verify the per-op signature on
//! `/vitonomi/chunks/1.0.0` request bodies. The vault caches results
//! by `(cluster_id, user_id)` so the round-trip happens at most once
//! per user per vault session.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use vitonomi_core::crypto::pq::MlDsa65PublicKey;
use vitonomi_core::encoding::hex_decode;
use vitonomi_core::types::{ClusterId, UserId};

use crate::routes::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentityPubkey {
    pub user_id: UserId,
    pub identity_pubkey: MlDsa65PublicKey,
}

/// `GET /v1/clusters/{cluster_id_hex}/users/{user_id_hex}/identity-pubkey`
pub async fn get_identity_pubkey(
    State(state): State<AppState>,
    Path((cluster_id_hex, user_id_hex)): Path<(String, String)>,
) -> Result<Json<UserIdentityPubkey>, ApiError> {
    let cluster_id = parse_cluster_id(&cluster_id_hex).ok_or_else(|| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "validation.invalid".into(),
        message: "invalid cluster_id hex".into(),
    })?;
    let user_id = parse_user_id(&user_id_hex).ok_or_else(|| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "validation.invalid".into(),
        message: "invalid user_id hex".into(),
    })?;
    let pk = state
        .control_plane
        .get_user_identity_pubkey(&cluster_id, &user_id)
        .await?;
    Ok(Json(UserIdentityPubkey {
        user_id,
        identity_pubkey: pk,
    }))
}

fn parse_cluster_id(s: &str) -> Option<ClusterId> {
    let bytes = hex_decode(s).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(ClusterId(arr))
}

fn parse_user_id(s: &str) -> Option<UserId> {
    let bytes = hex_decode(s).ok()?;
    let arr: [u8; 16] = bytes.as_slice().try_into().ok()?;
    Some(UserId(arr))
}
