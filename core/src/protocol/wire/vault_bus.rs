//! Vault-bus WebSocket frame types. All frames are length-prefixed
//! CBOR (4-byte LE length header).

use serde::{Deserialize, Serialize};

use crate::crypto::admin_chain::AdminChainEntry;
use crate::crypto::challenge::Challenge;
use crate::crypto::pq::MlDsa65Signature;
use crate::types::VaultId;

/// First frame from the hub on connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeFrame {
    pub challenge: Challenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponseFrame {
    pub vault_id: VaultId,
    pub signature: MlDsa65Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEstablishedFrame {
    pub session_id: String,
    pub chain_head: AdminChainEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatFrame {
    pub vault_id: VaultId,
    pub ts_ms: u64,
    pub signature: MlDsa65Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAppendFrame {
    pub entry: AdminChainEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorFrame {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectFrame {
    pub reason: String,
}

/// Periodic peer-state advertise. Sent on every reconnect by both
/// hub and vault; vault is authoritative on disagreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainAdvertiseFrame {
    pub cluster_id: crate::types::ClusterId,
    pub highest_seq: u64,
    #[serde(with = "serde_bytes")]
    pub head_hash: Vec<u8>,
}

/// Top-level frame enum with a `kind` discriminator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BusFrame {
    Challenge(ChallengeFrame),
    ChallengeResponse(ChallengeResponseFrame),
    SessionEstablished(SessionEstablishedFrame),
    Heartbeat(HeartbeatFrame),
    ChainAppend(ChainAppendFrame),
    ChainAdvertise(ChainAdvertiseFrame),
    Error(ErrorFrame),
    Disconnect(DisconnectFrame),
}
