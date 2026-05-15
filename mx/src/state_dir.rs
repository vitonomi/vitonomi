//! `vitonomi-mx` data directory layout + perm enforcement.
//!
//! ```text
//! <data_dir>/
//!   identity.bin     ML-DSA-65 relay keypair (32-byte seed)
//!   tls/
//!     cert.pem       wildcard TLS cert (rcgen-generated in dev,
//!     key.pem        operator-supplied in prod)
//! ```
//!
//! All files MUST be mode 0600. Parent directories MUST NOT be
//! world-writable. The relay refuses to start if either invariant
//! is broken (mirrors the vault's policy).

use std::fs;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};

/// `<data_dir>/identity.bin` — ML-DSA-65 relay keypair seed.
#[must_use]
pub fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.bin")
}

/// `<data_dir>/tls/cert.pem`.
#[must_use]
pub fn tls_cert_path(data_dir: &Path) -> PathBuf {
    data_dir.join("tls").join("cert.pem")
}

/// `<data_dir>/tls/key.pem`.
#[must_use]
pub fn tls_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("tls").join("key.pem")
}

/// Create the data directory if missing. Mode 0700; refuses to
/// proceed if the dir is world-writable.
///
/// # Errors
///
/// File-system errors or perm violations.
pub fn ensure_data_dir(data_dir: &Path) -> anyhow::Result<()> {
    if !data_dir.exists() {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("create data dir {}", data_dir.display()))?;
        fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))
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
    let tls_dir = data_dir.join("tls");
    if !tls_dir.exists() {
        fs::create_dir_all(&tls_dir)
            .with_context(|| format!("create tls dir {}", tls_dir.display()))?;
        fs::set_permissions(&tls_dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", tls_dir.display()))?;
    }
    Ok(())
}

/// Verify a file is mode 0600.
///
/// # Errors
///
/// Wrong perms or stat failure.
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
        let mut f = fs::OpenOptions::new()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_data_dir_creates_with_correct_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("mx-data");
        ensure_data_dir(&dir).unwrap();
        assert!(dir.exists());
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn ensure_data_dir_refuses_world_writable() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("mx-data");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let err = ensure_data_dir(&dir).unwrap_err();
        assert!(err.to_string().contains("world-writable"));
    }

    #[test]
    fn write_secure_round_trips_with_mode_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("file.bin");
        write_secure(&path, b"hello").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }
}
