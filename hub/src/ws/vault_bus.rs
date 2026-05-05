//! `/v1/vault-bus` WebSocket endpoint. Implements the handshake
//! described in `../../docs/protocol.md`:
//! Challenge (hub → vault) → ChallengeResponse (vault → hub) →
//! SessionEstablished (hub → vault) → Heartbeat / ChainAdvertise /
//! Disconnect frames thereafter.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use std::time::Duration;

use vitonomi_core::crypto::challenge::{verify_challenge, Challenge};
use vitonomi_core::encoding::{cbor_from_slice, cbor_to_vec};
use vitonomi_core::protocol::wire::vault_bus::{
    BusFrame, ChallengeFrame, DisconnectFrame, ErrorFrame, SessionEstablishedFrame,
};

use crate::state::AppState;

/// Subprotocol identifier negotiated via `Sec-WebSocket-Protocol`.
pub const SUBPROTOCOL: &str = "vitonomi.vault-bus.v1";

/// Heartbeat-deadline timeout per spec (60 s = 2 × 30 s heartbeat
/// interval). After this without a frame, hub closes.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

pub async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.protocols([SUBPROTOCOL])
        .on_upgrade(move |socket| handle_session(socket, state))
}

async fn handle_session(mut socket: WebSocket, state: AppState) {
    if let Err(e) = run_session(&mut socket, &state).await {
        tracing::warn!(error = %e, "vault-bus session ended with error");
        let _ = send_frame(
            &mut socket,
            &BusFrame::Error(ErrorFrame {
                code: e.code,
                message: e.message,
            }),
        )
        .await;
        let _ = send_frame(
            &mut socket,
            &BusFrame::Disconnect(DisconnectFrame {
                reason: "error".into(),
            }),
        )
        .await;
    }
    let _ = socket.close().await;
}

async fn run_session(socket: &mut WebSocket, state: &AppState) -> Result<(), SessionError> {
    // 1. Send Challenge.
    let now_ms = unix_now_ms();
    let challenge = Challenge::generate(now_ms).map_err(|e| SessionError {
        code: "internal".into(),
        message: format!("challenge: {e}"),
    })?;
    send_frame(
        socket,
        &BusFrame::Challenge(ChallengeFrame {
            challenge: challenge.clone(),
        }),
    )
    .await?;

    // 2. Receive ChallengeResponse.
    let resp = recv_frame(socket).await?;
    let cr = match resp {
        BusFrame::ChallengeResponse(cr) => cr,
        other => {
            return Err(SessionError {
                code: "protocol.unexpected_frame".into(),
                message: format!("expected ChallengeResponse, got {:?}", frame_kind(&other)),
            });
        }
    };

    // 3. Verify against stored vault pubkey.
    let pk = state
        .control_plane
        .get_vault_pubkey(&cr.vault_id)
        .await
        .map_err(|_| SessionError {
            code: "auth.unknown_vault".into(),
            message: "vault not registered".into(),
        })?;
    verify_challenge(&pk, &challenge, &cr.signature).map_err(|_| SessionError {
        code: "auth.signature_invalid".into(),
        message: "challenge response signature invalid".into(),
    })?;

    // 4. Send SessionEstablished. The chain head is fetched via a
    //    side-channel (REST `GET /v1/admin-chain/{cluster_id}/head`
    //    in the test harness); for the bus we send a synthetic
    //    SessionEstablished that the test driver verifies.
    let session_id = format!("session-{}", unix_now_ms());
    // Look up *some* chain head to populate. Real impl requires
    // resolving cluster_id from vault_id; for now we use a sentinel
    // that the smoke test ignores.
    let chain_head = state
        .control_plane
        .get_chain_head_for_vault(&cr.vault_id)
        .await
        .map_err(|_| SessionError {
            code: "internal".into(),
            message: "vault has no cluster chain head".into(),
        })?;
    send_frame(
        socket,
        &BusFrame::SessionEstablished(SessionEstablishedFrame {
            session_id,
            chain_head,
        }),
    )
    .await?;

    // 5. Loop: heartbeats, chain advertises, etc. Idle-timeout = 90 s.
    loop {
        let next = tokio::time::timeout(IDLE_TIMEOUT, recv_frame(socket)).await;
        let frame = match next {
            Err(_) => {
                return Err(SessionError {
                    code: "auth.idle_timeout".into(),
                    message: "no frame within IDLE_TIMEOUT".into(),
                });
            }
            Ok(Err(e)) => return Err(e),
            Ok(Ok(f)) => f,
        };
        match frame {
            BusFrame::Heartbeat(hb) => {
                let pk2 = state
                    .control_plane
                    .get_vault_pubkey(&hb.vault_id)
                    .await
                    .map_err(|_| SessionError {
                        code: "auth.unknown_vault".into(),
                        message: "vault not registered".into(),
                    })?;
                let mut signed = Vec::with_capacity(16 + 8);
                signed.extend_from_slice(&hb.vault_id.0);
                signed.extend_from_slice(&hb.ts_ms.to_be_bytes());
                if vitonomi_core::crypto::pq::ml_dsa_65_verify(&pk2, &hb.signature, &signed)
                    .is_err()
                {
                    return Err(SessionError {
                        code: "auth.heartbeat_invalid".into(),
                        message: "heartbeat signature invalid".into(),
                    });
                }
                let _ = state
                    .control_plane
                    .touch_vault_last_seen(&hb.vault_id, hb.ts_ms)
                    .await;
            }
            BusFrame::ChainAdvertise(_) => {
                // Hub-side advertise reconciliation lands when peer
                // gossip ships in v1.1+. For now, log + ignore.
                tracing::debug!("received ChainAdvertise from vault");
            }
            BusFrame::Disconnect(d) => {
                tracing::info!(reason = %d.reason, "vault disconnected");
                return Ok(());
            }
            other => {
                return Err(SessionError {
                    code: "protocol.unexpected_frame".into(),
                    message: format!("unexpected frame: {:?}", frame_kind(&other)),
                });
            }
        }
    }
}

async fn send_frame(socket: &mut WebSocket, frame: &BusFrame) -> Result<(), SessionError> {
    let cbor = cbor_to_vec(frame).map_err(|e| SessionError {
        code: "protocol.malformed".into(),
        message: format!("encode frame: {e}"),
    })?;
    let mut out = Vec::with_capacity(4 + cbor.len());
    let len: u32 = cbor.len().try_into().map_err(|_| SessionError {
        code: "protocol.frame_too_large".into(),
        message: "frame > u32::MAX".into(),
    })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&cbor);
    socket
        .send(Message::Binary(out.into()))
        .await
        .map_err(|e| SessionError {
            code: "protocol.send_failed".into(),
            message: format!("{e}"),
        })?;
    Ok(())
}

async fn recv_frame(socket: &mut WebSocket) -> Result<BusFrame, SessionError> {
    let msg = socket
        .next()
        .await
        .ok_or(SessionError {
            code: "protocol.closed".into(),
            message: "socket closed".into(),
        })?
        .map_err(|e| SessionError {
            code: "protocol.recv_failed".into(),
            message: format!("{e}"),
        })?;
    let bytes = match msg {
        Message::Binary(b) => b,
        Message::Close(_) => {
            return Err(SessionError {
                code: "protocol.closed".into(),
                message: "peer closed".into(),
            });
        }
        _ => {
            return Err(SessionError {
                code: "protocol.malformed".into(),
                message: "expected binary frame".into(),
            });
        }
    };
    if bytes.len() < 4 {
        return Err(SessionError {
            code: "protocol.malformed".into(),
            message: "frame shorter than 4-byte length prefix".into(),
        });
    }
    let len_bytes: [u8; 4] = bytes[..4].try_into().map_err(|_| SessionError {
        code: "protocol.malformed".into(),
        message: "len prefix slice".into(),
    })?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if bytes.len() != 4 + len {
        return Err(SessionError {
            code: "protocol.malformed".into(),
            message: format!(
                "len prefix says {} but frame body is {}",
                len,
                bytes.len() - 4
            ),
        });
    }
    let frame: BusFrame = cbor_from_slice(&bytes[4..]).map_err(|e| SessionError {
        code: "protocol.malformed".into(),
        message: format!("decode CBOR: {e}"),
    })?;
    Ok(frame)
}

fn frame_kind(f: &BusFrame) -> &'static str {
    match f {
        BusFrame::Challenge(_) => "Challenge",
        BusFrame::ChallengeResponse(_) => "ChallengeResponse",
        BusFrame::SessionEstablished(_) => "SessionEstablished",
        BusFrame::Heartbeat(_) => "Heartbeat",
        BusFrame::ChainAppend(_) => "ChainAppend",
        BusFrame::ChainAdvertise(_) => "ChainAdvertise",
        BusFrame::Error(_) => "Error",
        BusFrame::Disconnect(_) => "Disconnect",
    }
}

fn unix_now_ms() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
struct SessionError {
    code: String,
    message: String,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
