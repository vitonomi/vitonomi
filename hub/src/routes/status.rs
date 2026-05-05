//! `GET /v1/status` — hub status / liveness probe. Unauthenticated.
//! MUST NOT leak cluster count, DB state, or any per-cluster info.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct StatusResponse {
    pub status: &'static str,
    pub version: &'static str,
}

pub async fn get_status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok",
        version: state.version,
    })
}
