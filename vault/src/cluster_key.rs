//! Persistence for the vault's copy of the `cluster_shared_key`.
//!
//! Written during `accept` after the vault opens the invite's
//! `sealed_cluster_key` (K2 delivery; see
//! `vitonomi_core::crypto::invite_kek`). Loaded by every command
//! that needs to seal/unseal cluster-scoped material — admin-chain
//! inner payloads, vault names, and (Phase 1+) records.
//!
//! Stored as raw 32 bytes at `<data_dir>/cluster_shared_key.bin`,
//! mode 0600. Refuses to read with any other perms.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::cluster_keys::ClusterSharedKey;

use crate::state_dir;

/// Persist the cluster shared key. Atomically writes a 0600 file.
///
/// # Errors
///
/// File-system errors.
pub fn store(data_dir: &Path, key: &ClusterSharedKey) -> anyhow::Result<()> {
    if key.as_bytes().len() != ClusterSharedKey::LEN {
        return Err(anyhow!(
            "cluster_shared_key must be {} bytes; got {}",
            ClusterSharedKey::LEN,
            key.as_bytes().len()
        ));
    }
    let path = state_dir::cluster_shared_key_path(data_dir);
    state_dir::write_secure(&path, key.as_bytes())?;
    Ok(())
}

/// Load the cluster shared key. Refuses if perms aren't 0600 or if
/// the file isn't exactly 32 bytes.
///
/// # Errors
///
/// File-system errors, perm violations, length mismatch.
pub fn load(data_dir: &Path) -> anyhow::Result<ClusterSharedKey> {
    let path = state_dir::cluster_shared_key_path(data_dir);
    state_dir::enforce_file_perms_0600(&path)?;
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    if bytes.len() != ClusterSharedKey::LEN {
        return Err(anyhow!(
            "cluster_shared_key.bin is {} bytes; expected {}",
            bytes.len(),
            ClusterSharedKey::LEN
        ));
    }
    Ok(ClusterSharedKey(bytes))
}

/// Returns `true` if the cluster shared key has been persisted.
#[must_use]
pub fn exists(data_dir: &Path) -> bool {
    state_dir::cluster_shared_key_path(data_dir).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        state_dir::ensure_data_dir(d.path()).unwrap();
        d
    }

    #[test]
    fn store_then_load_round_trips() {
        let dir = fresh_dir();
        let key = ClusterSharedKey(vec![0x42u8; 32]);
        store(dir.path(), &key).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.as_bytes(), key.as_bytes());
    }

    #[test]
    fn missing_file_errors() {
        let dir = fresh_dir();
        assert!(load(dir.path()).is_err());
        assert!(!exists(dir.path()));
    }

    #[test]
    fn exists_after_store() {
        let dir = fresh_dir();
        let key = ClusterSharedKey(vec![1u8; 32]);
        assert!(!exists(dir.path()));
        store(dir.path(), &key).unwrap();
        assert!(exists(dir.path()));
    }

    #[test]
    fn refuses_wrong_length() {
        let dir = fresh_dir();
        // Bypass `store()` (which length-checks) by writing directly.
        state_dir::write_secure(&state_dir::cluster_shared_key_path(dir.path()), &[0u8; 16])
            .unwrap();
        assert!(load(dir.path()).is_err());
    }

    #[test]
    fn refuses_world_readable_perms() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = fresh_dir();
        let key = ClusterSharedKey(vec![2u8; 32]);
        store(dir.path(), &key).unwrap();
        // Loosen perms to 0644 to simulate tampering.
        std::fs::set_permissions(
            state_dir::cluster_shared_key_path(dir.path()),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(load(dir.path()).is_err());
    }
}
