//! Vault-bus WebSocket frame types. All frames are length-prefixed
//! CBOR (4-byte LE length header).

use serde::{Deserialize, Serialize};

use crate::crypto::admin_chain::AdminChainEntry;
use crate::crypto::challenge::Challenge;
use crate::crypto::pq::MlDsa65Signature;
use crate::types::VaultId;

/// Cadence at which an active vault sends a signed `Heartbeat` frame
/// to the hub. The vault binary uses this directly; hub-side
/// liveness windows derive from it via [`idle_timeout_secs`].
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// A vault is considered offline after this many heartbeat intervals
/// pass with no frame from it. Combined with `HEARTBEAT_INTERVAL_SECS`
/// in [`idle_timeout_secs`].
pub const OFFLINE_AFTER_MISSED_HEARTBEATS: u64 = 2;

/// Hub-side idle timeout: how long the hub waits for a frame before
/// closing the WS session, AND how stale `last_seen_ms` may be before
/// `list_vaults` reports the vault as `Offline`. Single source of
/// truth so the two derivations cannot drift.
#[must_use]
pub const fn idle_timeout_secs() -> u64 {
    HEARTBEAT_INTERVAL_SECS * OFFLINE_AFTER_MISSED_HEARTBEATS
}

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

/// Vault → hub: replace this vault's advertised libp2p multiaddrs.
/// Carries a signed `ts_ms` for replay defence; the hub binds the
/// vault identity to the active WS session already, so this frame's
/// signature is defence-in-depth.
///
/// The hub stores the resulting set in `VaultRecord::multiaddrs` so
/// clients calling `GET /v1/vaults` find it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvertiseAddrsFrame {
    pub vault_id: VaultId,
    pub multiaddrs: Vec<String>,
    pub ts_ms: u64,
    pub signature: MlDsa65Signature,
}

/// Build the bytes the vault signs for an `AdvertiseAddrsFrame`.
/// Stable layout: `vault_id || ts_ms_be8 || u32-BE addr count ||
/// (u32-BE len || addr_bytes)*`.
#[must_use]
pub fn advertise_addrs_signed_bytes(
    vault_id: &VaultId,
    multiaddrs: &[String],
    ts_ms: u64,
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(16 + 8 + 4 + multiaddrs.iter().map(|s| 4 + s.len()).sum::<usize>());
    buf.extend_from_slice(&vault_id.0);
    buf.extend_from_slice(&ts_ms.to_be_bytes());
    buf.extend_from_slice(&(multiaddrs.len() as u32).to_be_bytes());
    for addr in multiaddrs {
        buf.extend_from_slice(&(addr.len() as u32).to_be_bytes());
        buf.extend_from_slice(addr.as_bytes());
    }
    buf
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
    AdvertiseAddrs(AdvertiseAddrsFrame),
    Error(ErrorFrame),
    Disconnect(DisconnectFrame),
}
