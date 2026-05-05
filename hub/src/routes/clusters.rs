//! `POST /v1/clusters` (register) and `POST /v1/clusters/restore`.
//! Both are unauthenticated — admission is gated by signed envelopes.

use axum::extract::State;
use axum::Json;

use vitonomi_core::protocol::hub_control_plane::{
    ClusterRegisterRequest, ClusterRegisterResponse, ClusterRestoreRequest,
};

use crate::routes::errors::ApiError;
use crate::state::AppState;

pub async fn post_register(
    State(state): State<AppState>,
    Json(req): Json<ClusterRegisterRequest>,
) -> Result<Json<ClusterRegisterResponse>, ApiError> {
    let resp = state.control_plane.register_cluster(req).await?;
    Ok(Json(resp))
}

pub async fn post_restore(
    State(state): State<AppState>,
    Json(req): Json<ClusterRestoreRequest>,
) -> Result<Json<ClusterRegisterResponse>, ApiError> {
    let resp = state.control_plane.restore_cluster(req).await?;
    Ok(Json(resp))
}
