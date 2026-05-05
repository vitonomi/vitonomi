//! Scheme A login. The hub never sees passwords or auth-keys; it
//! only verifies that a signature over a fresh challenge matches the
//! stored identity pubkey.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use vitonomi_core::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
};

use crate::routes::errors::ApiError;
use crate::state::AppState;

pub async fn post_login_start(
    State(state): State<AppState>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, ApiError> {
    let resp = state.control_plane.login_start(req).await?;
    Ok(Json(resp))
}

pub async fn post_login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<Json<LoginFinishResponse>, ApiError> {
    let resp = state.control_plane.login_finish(req).await?;
    Ok(Json(resp))
}

pub async fn post_logout(
    State(state): State<AppState>,
    crate::auth::BearerSession(token): crate::auth::BearerSession,
) -> Result<StatusCode, ApiError> {
    state.control_plane.logout(&token).await?;
    Ok(StatusCode::NO_CONTENT)
}
