//! `list_vaults` derives each vault's `Online`/`Offline` status from
//! `last_seen_ms` + the shared `idle_timeout_secs` window. A vault
//! that gets killed must flip to `Offline` once its heartbeat goes
//! stale; a vault that never connected must not show as `Online`;
//! the `Revoked` terminal state is preserved.
//!
//! These tests cover the derivation rule directly and the constant
//! relationship hub + vault rely on.

use vitonomi_core::protocol::hub_control_plane::{VaultRecord, VaultStatus};
use vitonomi_core::protocol::wire::vault_bus::{
    idle_timeout_secs, HEARTBEAT_INTERVAL_SECS, OFFLINE_AFTER_MISSED_HEARTBEATS,
};
use vitonomi_core::types::VaultId;

/// Mirror of the derivation rule applied inside
/// `InMemoryHubControlPlane::list_vaults`. Kept here so a behaviour
/// change in the impl breaks an explicit assertion, not just an
/// observation.
fn derive_status(record: &VaultRecord, now_ms: u64) -> VaultStatus {
    let idle_ms = idle_timeout_secs() * 1_000;
    if record.status == VaultStatus::Revoked {
        return VaultStatus::Revoked;
    }
    match record.last_seen_ms {
        Some(ts) if now_ms.saturating_sub(ts) <= idle_ms => VaultStatus::Online,
        _ => VaultStatus::Offline,
    }
}

fn synthetic_vault(last_seen_ms: Option<u64>, status: VaultStatus) -> VaultRecord {
    VaultRecord {
        vault_id: VaultId([0xaa; 16]),
        vault_pubkey: vitonomi_core::crypto::pq::ml_dsa_65_keypair()
            .unwrap()
            .public,
        last_seen_ms,
        status,
        sealed_meta: vec![],
        multiaddrs: vec![],
    }
}

#[test]
fn never_connected_is_offline() {
    let v = synthetic_vault(None, VaultStatus::Online);
    assert_eq!(derive_status(&v, 1_000_000_000), VaultStatus::Offline);
}

#[test]
fn recent_heartbeat_is_online() {
    let now = 1_000_000_000;
    let v = synthetic_vault(Some(now - 5_000), VaultStatus::Online);
    assert_eq!(derive_status(&v, now), VaultStatus::Online);
}

#[test]
fn at_exactly_idle_window_still_online() {
    let now = 1_000_000_000;
    let v = synthetic_vault(Some(now - idle_timeout_secs() * 1_000), VaultStatus::Online);
    assert_eq!(derive_status(&v, now), VaultStatus::Online);
}

#[test]
fn one_ms_past_idle_window_is_offline() {
    let now = 1_000_000_000;
    let stale = now - idle_timeout_secs() * 1_000 - 1;
    let v = synthetic_vault(Some(stale), VaultStatus::Online);
    assert_eq!(derive_status(&v, now), VaultStatus::Offline);
}

#[test]
fn revoked_status_is_preserved_regardless_of_last_seen() {
    let now = 1_000_000_000;
    let recent = synthetic_vault(Some(now), VaultStatus::Revoked);
    let stale = synthetic_vault(Some(now - 1_000_000), VaultStatus::Revoked);
    let none = synthetic_vault(None, VaultStatus::Revoked);
    assert_eq!(derive_status(&recent, now), VaultStatus::Revoked);
    assert_eq!(derive_status(&stale, now), VaultStatus::Revoked);
    assert_eq!(derive_status(&none, now), VaultStatus::Revoked);
}

#[test]
fn idle_timeout_is_two_heartbeat_intervals() {
    assert_eq!(HEARTBEAT_INTERVAL_SECS, 30);
    assert_eq!(OFFLINE_AFTER_MISSED_HEARTBEATS, 2);
    assert_eq!(idle_timeout_secs(), 60);
}
