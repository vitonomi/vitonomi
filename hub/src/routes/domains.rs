//! Hub HTTP handlers for user-owned, DNS-verified domains (e.g.
//! `example.com`). The `Domain` record is unified — subdomain
//! claims and these DNS-verified entries share `DomainMetadata` with
//! an `is_custom` discriminator — but the lifecycles differ
//! (subdomain = one-shot claim; this surface = challenge-issue +
//! verify), so the URL prefix and the handlers live apart.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use vitonomi_core::protocol::wire::domains::{DomainChallenge, DomainRecord, DomainVerified};

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct AddDomainBody {
    pub domain: String,
}

pub async fn post_add_domain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Json(body): Json<AddDomainBody>,
) -> Result<Json<DomainChallenge>, ApiError> {
    let challenge = state
        .control_plane
        .add_domain(&token, &body.domain)
        .await?;
    Ok(Json(challenge))
}

pub async fn post_verify_domain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(domain): Path<String>,
) -> Result<Json<DomainVerified>, ApiError> {
    let v = state.control_plane.verify_domain(&token, &domain).await?;
    Ok(Json(v))
}

#[derive(Serialize)]
pub struct ListDomainsResponse {
    pub domains: Vec<DomainRecord>,
}

pub async fn get_list_domains(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
) -> Result<Json<ListDomainsResponse>, ApiError> {
    let domains = state.control_plane.list_domains(&token).await?;
    Ok(Json(ListDomainsResponse { domains }))
}

pub async fn delete_domain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(domain): Path<String>,
) -> Result<StatusCode, ApiError> {
    state.control_plane.remove_domain(&token, &domain).await?;
    Ok(StatusCode::NO_CONTENT)
}
