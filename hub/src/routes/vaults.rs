//! Vault directory + invite + accept routes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use vitonomi_core::protocol::hub_control_plane::VaultRecord;
use vitonomi_core::protocol::wire::accept::{
    AcceptRequest, AcceptResponse, CreateInviteRequest, CreateInviteResponse,
};

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct ListVaultsResponse {
    pub vaults: Vec<VaultRecord>,
}

pub async fn get_list(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
) -> Result<Json<ListVaultsResponse>, ApiError> {
    let vaults = state.control_plane.list_vaults(&token).await?;
    Ok(Json(ListVaultsResponse { vaults }))
}

pub async fn post_invite(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Json(req): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<CreateInviteResponse>), ApiError> {
    let resp = state.control_plane.create_vault_invite(&token, req).await?;
    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn post_accept(
    State(state): State<AppState>,
    Json(req): Json<AcceptRequest>,
) -> Result<(StatusCode, Json<AcceptResponse>), ApiError> {
    let resp = state.control_plane.accept_vault_invite(req).await?;
    Ok((StatusCode::CREATED, Json(resp)))
}
