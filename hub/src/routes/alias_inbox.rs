//! Hub HTTP handlers for the per-alias inbound queue (shape A):
//! mx-relay push, client fetch, client ack.
//!
//! The push endpoint is authenticated per-call by the embedded
//! `sig_mx_relay` (verified server-side against the registered
//! mx-relay pubkey) — not by a bearer session. Fetch and ack are
//! bearer-gated to the alias owner.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use vitonomi_core::protocol::wire::aliases::InboundEnvelope;
use vitonomi_core::protocol::wire::mx_relay_push::{MxRelayPushAck, SignedMxRelayPush};
use vitonomi_core::record::RecordId;

use crate::auth::BearerSession;
use crate::routes::errors::ApiError;
use crate::state::AppState;

pub async fn post_mx_relay_push_inbound(
    State(state): State<AppState>,
    Json(push): Json<SignedMxRelayPush>,
) -> Result<Json<MxRelayPushAck>, ApiError> {
    let ack = state.control_plane.mx_relay_push_inbound(push).await?;
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

fn parse_record_id(hex: &str) -> Result<RecordId, ApiError> {
    RecordId::from_hex(hex).map_err(|e| ApiError {
        status: StatusCode::BAD_REQUEST,
        code: "record_id.invalid".into(),
        message: e.to_string(),
    })
}
