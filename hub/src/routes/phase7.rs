//! Phase 7 axum handlers — subdomains, custom domains, alias
//! directory, per-alias inbox, relay push.
//!
//! Each handler is a thin wrapper around the matching
//! `HubControlPlane` trait method on `AppState.control_plane`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use vitonomi_core::protocol::wire::aliases::{AliasDirectoryEntry, InboundEnvelope};
use vitonomi_core::protocol::wire::domains::{DomainChallenge, DomainRecord, DomainVerified};
use vitonomi_core::protocol::wire::relay_push::{
    RegisterRelayRequest, RegisterRelayResponse, RelayPushAck, SignedRelayPush,
};
use vitonomi_core::protocol::wire::subdomains::{ManagedBaseDomains, SubdomainDirectoryEntry};
use vitonomi_core::record::RecordId;
use vitonomi_core::types::subdomain::{Subdomain, SubdomainClaim};

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

// ---- subdomains ---------------------------------------------------

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

// ---- custom domains ----------------------------------------------

#[derive(Deserialize)]
pub struct AddDomainBody {
    pub domain: String,
}

pub async fn post_add_custom_domain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Json(body): Json<AddDomainBody>,
) -> Result<Json<DomainChallenge>, ApiError> {
    let challenge = state
        .control_plane
        .add_custom_domain(&token, &body.domain)
        .await?;
    Ok(Json(challenge))
}

pub async fn post_verify_custom_domain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(domain): Path<String>,
) -> Result<Json<DomainVerified>, ApiError> {
    let v = state
        .control_plane
        .verify_custom_domain(&token, &domain)
        .await?;
    Ok(Json(v))
}

#[derive(Serialize)]
pub struct ListDomainsResponse {
    pub domains: Vec<DomainRecord>,
}

pub async fn get_list_custom_domains(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
) -> Result<Json<ListDomainsResponse>, ApiError> {
    let domains = state.control_plane.list_custom_domains(&token).await?;
    Ok(Json(ListDomainsResponse { domains }))
}

pub async fn delete_custom_domain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(domain): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .control_plane
        .remove_custom_domain(&token, &domain)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- alias directory ---------------------------------------------

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

// ---- per-alias inbox ----------------------------------------------

pub async fn post_relay_push(
    State(state): State<AppState>,
    Json(push): Json<SignedRelayPush>,
) -> Result<Json<RelayPushAck>, ApiError> {
    let ack = state.control_plane.relay_push_inbound(push).await?;
    Ok(Json(ack))
}

#[derive(Deserialize)]
pub struct InboxQuery {
    #[serde(default)]
    pub since: u64,
}

#[derive(Serialize)]
pub struct InboxFetchResponse {
    pub envelopes: Vec<InboundEnvelope>,
}

pub async fn get_alias_inbox(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(alias_id_hex): Path<String>,
    Query(q): Query<InboxQuery>,
) -> Result<Json<InboxFetchResponse>, ApiError> {
    let alias_id = parse_record_id(&alias_id_hex)?;
    let envelopes = state
        .control_plane
        .fetch_alias_inbox(&token, &alias_id, q.since)
        .await?;
    Ok(Json(InboxFetchResponse { envelopes }))
}

#[derive(Deserialize)]
pub struct InboxAckBody {
    pub up_to_seq: u64,
}

pub async fn post_alias_inbox_ack(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(alias_id_hex): Path<String>,
    Json(body): Json<InboxAckBody>,
) -> Result<StatusCode, ApiError> {
    let alias_id = parse_record_id(&alias_id_hex)?;
    state
        .control_plane
        .ack_alias_inbox(&token, &alias_id, body.up_to_seq)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- relay identity (admin-only at the trait level) --------------

pub async fn post_register_relay(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Json(req): Json<RegisterRelayRequest>,
) -> Result<Json<RegisterRelayResponse>, ApiError> {
    let resp = state
        .control_plane
        .register_relay_identity(&token, req)
        .await?;
    Ok(Json(resp))
}

fn parse_record_id(hex: &str) -> Result<RecordId, ApiError> {
    RecordId::from_hex(hex).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "record_id.invalid".into(),
        message: e.to_string(),
    })
}
