//! Hub HTTP handlers for the alias directory (`(alias_handle,
//! namespace) → AliasDirectoryEntry`). Public read; admin-signed
//! write. The relay's inbound queue depends on these entries —
//! lookups happen on every inbound mail.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use vitonomi_core::protocol::wire::aliases::AliasDirectoryEntry;

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

pub async fn post_publish_alias_pubkey(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Json(entry): Json<AliasDirectoryEntry>,
) -> Result<StatusCode, ApiError> {
    state
        .control_plane
        .publish_alias_pubkey(&token, entry)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_lookup_alias_pubkey(
    State(state): State<AppState>,
    Path((handle, namespace)): Path<(String, String)>,
) -> Result<Json<AliasDirectoryEntry>, ApiError> {
    let entry = state
        .control_plane
        .lookup_alias_pubkey(&handle, &namespace)
        .await?;
    Ok(Json(entry))
}

pub async fn delete_alias_pubkey(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path((handle, namespace)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state
        .control_plane
        .revoke_alias_pubkey(&token, &handle, &namespace)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
