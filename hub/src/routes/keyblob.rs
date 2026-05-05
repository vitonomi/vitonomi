//! `/v1/keyblob` — opaque key blob storage. Hub never decrypts.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use vitonomi_core::encoding::{b64url_decode, b64url_encode};
use vitonomi_core::errors::CoreError;

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct GetResponse {
    pub encrypted_key_blob: String,
}

#[derive(Debug, Deserialize)]
pub struct PutRequest {
    pub encrypted_key_blob: String,
}

pub async fn get(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
) -> Result<Json<GetResponse>, ApiError> {
    let bytes = state.control_plane.get_keyblob(&token).await?;
    Ok(Json(GetResponse {
        encrypted_key_blob: b64url_encode(&bytes),
    }))
}

pub async fn put(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Json(req): Json<PutRequest>,
) -> Result<StatusCode, ApiError> {
    let bytes = b64url_decode(&req.encrypted_key_blob)
        .map_err(|e| ApiError::from(CoreError::Protocol(e)))?;
    state.control_plane.put_keyblob(&token, bytes).await?;
    Ok(StatusCode::NO_CONTENT)
}
