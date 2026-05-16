//! Hub HTTP handler for `vitonomi-mx` relay identity registration.
//! Admin-only at the trait level — production gates on a
//! cluster-admin role on the bearer session.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use vitonomi_core::protocol::wire::mx_relay_push::RegisterMxRelayRequest;

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

pub async fn post_register_mx_relay(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Json(req): Json<RegisterMxRelayRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .control_plane
        .register_mx_relay_identity(&token, req)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
