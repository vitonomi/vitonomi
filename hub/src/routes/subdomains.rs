//! Hub HTTP handlers for managed-subdomain claims under a
//! hub-controlled base (e.g. `<sub>.vito.gg`). Thin wrappers
//! around the matching `HubControlPlane` trait methods.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use vitonomi_core::protocol::wire::subdomains::{ManagedBaseDomains, SubdomainDirectoryEntry};
use vitonomi_core::types::subdomain::{Subdomain, SubdomainClaim};

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

pub async fn post_claim_subdomain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Json(claim): Json<SubdomainClaim>,
) -> Result<StatusCode, ApiError> {
    state.control_plane.claim_subdomain(&token, claim).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_subdomain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path((base, sub)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let sub = Subdomain::parse(&sub).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "subdomain.invalid".into(),
        message: e.to_string(),
    })?;
    state
        .control_plane
        .release_subdomain(&token, &base, &sub)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_subdomain(
    State(state): State<AppState>,
    Path((base, sub)): Path<(String, String)>,
) -> Result<Json<SubdomainDirectoryEntry>, ApiError> {
    let sub = Subdomain::parse(&sub).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "subdomain.invalid".into(),
        message: e.to_string(),
    })?;
    let entry = state.control_plane.lookup_subdomain(&base, &sub).await?;
    Ok(Json(entry))
}

pub async fn get_managed_base_domains(
    State(state): State<AppState>,
) -> Result<Json<ManagedBaseDomains>, ApiError> {
    let bases = state.control_plane.list_managed_base_domains().await?;
    Ok(Json(ManagedBaseDomains { bases }))
}
