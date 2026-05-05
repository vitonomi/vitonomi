//! Admin chain export / head / append routes. The hub stores
//! sealed envelopes only.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;

use vitonomi_core::encoding::hex_decode;
use vitonomi_core::errors::{CoreError, ValidationError};
use vitonomi_core::protocol::wire::admin_chain::{
    ChainAppendRequest, ChainExport, ChainHeadResponse,
};
use vitonomi_core::types::ClusterId;

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct FromSeqQuery {
    #[serde(default)]
    pub from_seq: u64,
}

fn parse_cluster_id(s: &str) -> Result<ClusterId, ApiError> {
    let bytes = hex_decode(s).map_err(|e| ApiError::from(CoreError::Protocol(e)))?;
    if bytes.len() != 32 {
        return Err(ApiError::from(CoreError::Validation(
            ValidationError::Other(format!(
                "cluster_id must be 32 bytes hex, got {} bytes",
                bytes.len()
            )),
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(ClusterId(arr))
}

pub async fn get_head(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(cluster_id): Path<String>,
) -> Result<Json<ChainHeadResponse>, ApiError> {
    let cid = parse_cluster_id(&cluster_id)?;
    let head = state
        .control_plane
        .get_admin_chain_head(&token, &cid)
        .await?;
    Ok(Json(ChainHeadResponse { head }))
}

pub async fn get_chain(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(cluster_id): Path<String>,
    Query(q): Query<FromSeqQuery>,
) -> Result<Json<ChainExport>, ApiError> {
    let cid = parse_cluster_id(&cluster_id)?;
    let entries = state
        .control_plane
        .get_admin_chain(&token, &cid, q.from_seq)
        .await?;
    Ok(Json(ChainExport {
        cluster_id: cid,
        entries,
    }))
}

pub async fn post_append(
    State(state): State<AppState>,
    BearerSession(token): BearerSession,
    Path(cluster_id): Path<String>,
    Json(req): Json<ChainAppendRequest>,
) -> Result<StatusCode, ApiError> {
    let cid = parse_cluster_id(&cluster_id)?;
    state
        .control_plane
        .append_admin_chain(&token, &cid, req.entries)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
