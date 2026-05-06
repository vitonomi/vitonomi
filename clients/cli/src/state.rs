//! Per-cluster admin-side state. Persisted at
//! `$XDG_STATE_HOME/vitonomi/state.json` (mode 0600). Contents:
//!
//! - `username` — local identity (raw, never sent to hub)
//! - `hub_url` — currently active hub
//! - `cluster_id` — opaque 32-byte hash, hub-readable
//! - `cluster_admin_pubkey` — used to verify chain entries offline
//! - `cluster_pepper` — required to compute lookup_id locally
//! - `session_token` + `session_expires_at_ms` — current session
//! - `user_id` — opaque hub-assigned id
//! - `encrypted_key_blob_cache` — last-fetched blob bytes, so
//!   admin operations don't need a fresh fetch on every call

use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context as _};
use serde::{Deserialize, Serialize};

use vitonomi_core::crypto::cluster_keys::ClusterPepper;
use vitonomi_core::crypto::pq::MlDsa65PublicKey;
use vitonomi_core::types::{ClusterId, SessionToken, UserId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliState {
    pub username: String,
    pub hub_url: String,
    pub cluster_id: ClusterId,
    pub cluster_admin_pubkey: MlDsa65PublicKey,
    #[serde(with = "serde_bytes")]
    pub cluster_pepper: Vec<u8>,
    pub user_id: UserId,
    pub session_token: Option<SessionToken>,
    pub session_expires_at_ms: u64,
    /// Most recent encrypted key blob fetched from the hub. Cached
    /// locally so admin operations (e.g. `vault invite`) can
    /// re-prompt the password and unseal without a fresh
    /// login_start round-trip.
    #[serde(with = "serde_bytes")]
    pub encrypted_key_blob: Vec<u8>,
}

impl CliState {
    #[must_use]
    pub fn pepper(&self) -> ClusterPepper {
        ClusterPepper(self.cluster_pepper.clone())
    }
}

/// `$XDG_STATE_HOME/vitonomi/state.json`.
///
/// # Errors
///
/// Returns an error if no state home can be resolved.
pub fn default_state_path() -> anyhow::Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "vitonomi", "vitonomi")
        .ok_or_else(|| anyhow!("cannot resolve $XDG_STATE_HOME for vitonomi"))?;
    Ok(dirs.data_local_dir().join("state.json"))
}

/// Resolve the on-disk state path: explicit cli config override
/// first, otherwise XDG default.
///
/// # Errors
///
/// As [`default_state_path`].
pub fn resolve_state_path(state_dir: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(d) = state_dir {
        return Ok(d.join("state.json"));
    }
    default_state_path()
}

/// Load state from disk. Refuses to read if perms are wrong.
///
/// # Errors
///
/// IO / decode / perm-violation failures, or `NotFound` if the
/// file doesn't exist (caller must distinguish via
/// `e.downcast_ref::<std::io::Error>()`).
pub fn load(path: &Path) -> anyhow::Result<CliState> {
    if !path.exists() {
        bail!(
            "{} not found — run `cluster create` or `login` first",
            path.display()
        );
    }
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "{} has mode {:#o}; refusing (must be 0600)",
            path.display(),
            mode
        );
    }
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).context("decode state.json")
}

/// Atomically save state to disk with mode 0600.
///
/// # Errors
///
/// IO / serialisation failures.
pub fn save(path: &Path, state: &CliState) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create state dir {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(state).context("encode state")?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        use std::io::Write as _;
        f.write_all(&bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Delete the state file (used by `logout`).
///
/// # Errors
///
/// IO failures other than NotFound.
pub fn delete(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("remove {}: {e}", path.display())),
    }
}
