//! Short-lived on-disk cache of unsealed `MasterSecretKeys`.
//!
//! Without a cache, every CLI command that needs `identity_sk` or the
//! AEAD master re-prompts the user for the cluster password — the
//! session token only authenticates to the hub and can't help with
//! local crypto. This module fixes that: after a successful unseal
//! (login / cluster create / cluster restore / any command that
//! prompts), we persist the unsealed `MasterSecretKeys` to
//! `<state_dir>/secret_cache.bin` (mode 0600) with a TTL. Subsequent
//! commands within the TTL skip the prompt.
//!
//! # Threat model
//!
//! - The cache lives in the user's data dir, mode 0600. Anyone with
//!   read access to that file gets the unsealed master secrets.
//! - This is **the same threat model as ssh-agent / gpg-agent**:
//!   processes running as the same uid can already inspect each
//!   other's memory via `ptrace` etc. Caching on disk under 0600
//!   doesn't broaden the attack surface materially.
//! - The cache is **bound to a `cluster_id`** — restoring or
//!   creating a different cluster invalidates the existing cache.
//! - The cache has a **TTL** — by default we tie it to the session
//!   token's expiry, so it dies along with the hub session.
//! - `vitonomi-cli logout` clears the cache.
//!
//! # File format
//!
//! Deterministic CBOR of:
//!
//! ```text
//! SecretCacheEntry { format_version, cluster_id, expires_at_ms, secrets }
//! ```

use std::fs;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _, Result};
use serde::{Deserialize, Serialize};

use vitonomi_core::crypto::keyblob::decrypt_with_password;
use vitonomi_core::crypto::keys::MasterSecretKeys;
use vitonomi_core::encoding::{cbor_from_slice, cbor_to_vec};
use vitonomi_core::types::{ClusterId, FormatVersion};

use crate::prompts::Prompts;
use crate::state::CliState;

/// Default cache TTL when no session-bound expiry is supplied: 1 hour.
pub const DEFAULT_TTL_MS: u64 = 60 * 60 * 1000;

/// File name under `<state_dir>`.
const CACHE_FILE: &str = "secret_cache.bin";

#[derive(Serialize, Deserialize)]
struct SecretCacheEntry {
    format_version: FormatVersion,
    cluster_id: ClusterId,
    expires_at_ms: u64,
    secrets: MasterSecretKeys,
}

#[must_use]
fn cache_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CACHE_FILE)
}

#[must_use]
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0)
}

/// Try to read the cache for `cluster_id`. Returns `None` if the file
/// doesn't exist, perms are wrong, TTL has expired, the cluster_id
/// doesn't match, or any decode step fails (the latter is treated as
/// a stale-cache miss, not an error — the caller will fall back to
/// prompting).
#[must_use]
pub fn try_read(state_dir: &Path, cluster_id: &ClusterId) -> Option<MasterSecretKeys> {
    let path = cache_path(state_dir);
    if !path.exists() {
        return None;
    }
    let meta = fs::metadata(&path).ok()?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        // Refuse to use a cache file with wrong perms — somebody else
        // may have written / read it.
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    let entry: SecretCacheEntry = cbor_from_slice(&bytes).ok()?;
    if &entry.cluster_id != cluster_id {
        return None;
    }
    if entry.expires_at_ms <= now_ms() {
        return None;
    }
    Some(entry.secrets)
}

/// Atomically persist `secrets` to the cache. Mode 0600. The cache
/// expires at `min(now + DEFAULT_TTL_MS, hard_deadline_ms)` if a
/// hard deadline (e.g. session-token expiry) is supplied.
pub fn write(
    state_dir: &Path,
    cluster_id: &ClusterId,
    secrets: &MasterSecretKeys,
    hard_deadline_ms: Option<u64>,
) -> Result<()> {
    fs::create_dir_all(state_dir)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;
    let soft = now_ms().saturating_add(DEFAULT_TTL_MS);
    let expires_at_ms = match hard_deadline_ms {
        Some(deadline) => soft.min(deadline),
        None => soft,
    };
    let entry = SecretCacheEntry {
        format_version: FormatVersion::V1,
        cluster_id: *cluster_id,
        expires_at_ms,
        secrets: secrets.clone(),
    };
    let bytes = cbor_to_vec(&entry).map_err(|e| anyhow!("encode secret cache: {e}"))?;
    let path = cache_path(state_dir);
    let tmp = path.with_extension("bin.tmp");
    {
        let mut f = fs::OpenOptions::new()
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
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Delete the cache. Idempotent.
pub fn clear(state_dir: &Path) -> Result<()> {
    match fs::remove_file(cache_path(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("clear secret cache: {e}")),
    }
}

/// Resolve `MasterSecretKeys` for the current state:
///
/// 1. Try the on-disk cache. If hot, return immediately.
/// 2. Otherwise prompt the user, decrypt the encrypted key blob, and
///    refresh the cache so the next command doesn't have to prompt.
///
/// Use `state_dir = state_path.parent()` from the caller.
pub fn read_or_prompt<P: Prompts + ?Sized>(
    state: &CliState,
    state_dir: &Path,
    prompts: &mut P,
) -> Result<MasterSecretKeys> {
    if let Some(secrets) = try_read(state_dir, &state.cluster_id) {
        return Ok(secrets);
    }
    let password = prompts.password("Password", false)?;
    let secrets = decrypt_with_password(password.as_bytes(), &state.encrypted_key_blob)
        .map_err(|e| anyhow!("decrypt key blob (wrong password?): {e}"))?;
    // Best-effort refresh — if the cache write fails we still
    // succeed at returning the unsealed secrets.
    let _ = write(
        state_dir,
        &state.cluster_id,
        &secrets,
        Some(state.session_expires_at_ms),
    );
    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitonomi_core::crypto::keys::GenesisMaterial;

    fn fresh_secrets() -> (MasterSecretKeys, ClusterId) {
        let g = GenesisMaterial::generate().unwrap();
        let cluster_id = vitonomi_core::crypto::cluster::cluster_id_of(
            &vitonomi_core::crypto::keys::MasterPublicKeys::from(&g.master_keys).cluster_admin,
            FormatVersion::V1,
        );
        (MasterSecretKeys::from_genesis(&g), cluster_id)
    }

    #[test]
    fn round_trip_within_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, cid) = fresh_secrets();
        write(tmp.path(), &cid, &s, None).unwrap();
        let back = try_read(tmp.path(), &cid).expect("cache should be hot");
        assert_eq!(back.identity.0, s.identity.0);
    }

    #[test]
    fn miss_on_wrong_cluster_id() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, cid_a) = fresh_secrets();
        let (_, cid_b) = fresh_secrets();
        write(tmp.path(), &cid_a, &s, None).unwrap();
        assert!(try_read(tmp.path(), &cid_b).is_none());
    }

    #[test]
    fn miss_after_expiry() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, cid) = fresh_secrets();
        // expires_at_ms = 0 → already expired
        write(tmp.path(), &cid, &s, Some(0)).unwrap();
        assert!(try_read(tmp.path(), &cid).is_none());
    }

    #[test]
    fn clear_removes_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, cid) = fresh_secrets();
        write(tmp.path(), &cid, &s, None).unwrap();
        assert!(cache_path(tmp.path()).exists());
        clear(tmp.path()).unwrap();
        assert!(!cache_path(tmp.path()).exists());
        // Idempotent: second clear is also fine.
        clear(tmp.path()).unwrap();
    }

    #[test]
    fn write_uses_mode_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, cid) = fresh_secrets();
        write(tmp.path(), &cid, &s, None).unwrap();
        let mode = fs::metadata(cache_path(tmp.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn rejects_wrong_perms_silently() {
        let tmp = tempfile::tempdir().unwrap();
        let (s, cid) = fresh_secrets();
        write(tmp.path(), &cid, &s, None).unwrap();
        // Chmod to world-readable — should be treated as a miss.
        fs::set_permissions(cache_path(tmp.path()), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(try_read(tmp.path(), &cid).is_none());
    }
}
