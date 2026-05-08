//! Vault data directory layout and perms enforcement.
//!
//! ```text
//! <data_dir>/
//!   identity.bin            ML-DSA-65 vault keypair (32-byte seed)
//!   enrollment.json         post-accept state
//!   admin-chain/
//!     <seq>.cbor            one outer-envelope per file
//! ```
//!
//! All files MUST be mode 0600. Parent directory MUST NOT be
//! world-writable. Vault refuses to start if either invariant is
//! broken.

use std::fs;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};

/// `<data_dir>/identity.bin`.
#[must_use]
pub fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.bin")
}

/// `<data_dir>/enrollment.json`.
#[must_use]
pub fn enrollment_path(data_dir: &Path) -> PathBuf {
    data_dir.join("enrollment.json")
}

/// `<data_dir>/admin-chain/`.
#[must_use]
pub fn admin_chain_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("admin-chain")
}

/// `<data_dir>/cluster_shared_key.bin` — the AEAD key used to seal
/// chain inner payloads, vault names, and (Phase 1+) records. Written
/// during `accept` after the vault opens the invite's
/// `sealed_cluster_key`.
#[must_use]
pub fn cluster_shared_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("cluster_shared_key.bin")
}

/// Create the data directory if missing, enforcing 0700 on it and
/// 0600 on every file underneath.
///
/// # Errors
///
/// File-system errors or perm violations.
pub fn ensure_data_dir(data_dir: &Path) -> anyhow::Result<()> {
    if !data_dir.exists() {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("create data dir {}", data_dir.display()))?;
        fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", data_dir.display()))?;
    }
    let meta = fs::metadata(data_dir).with_context(|| format!("stat {}", data_dir.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o002 != 0 {
        bail!(
            "{} is world-writable (mode {:#o}); refusing to use",
            data_dir.display(),
            mode
        );
    }
    let admin_chain = admin_chain_dir(data_dir);
    if !admin_chain.exists() {
        fs::create_dir_all(&admin_chain)
            .with_context(|| format!("create admin-chain dir {}", admin_chain.display()))?;
        fs::set_permissions(&admin_chain, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", admin_chain.display()))?;
    }
    Ok(())
}

/// Verify that a file is mode 0600 and refuse otherwise. Used on
/// every read of identity / enrollment.
///
/// # Errors
///
/// File-system errors or perm violations.
pub fn enforce_file_perms_0600(path: &Path) -> anyhow::Result<()> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "{} has mode {:#o}; refusing to use (must be 0600)",
            path.display(),
            mode
        );
    }
    Ok(())
}

/// Atomically write `bytes` to `path` with mode 0600.
///
/// # Errors
///
/// File-system errors.
pub fn write_secure(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
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
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}
