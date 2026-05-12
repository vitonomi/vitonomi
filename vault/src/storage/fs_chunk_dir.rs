//! Filesystem layout for Autonomi-format chunks on the vault disk.
//!
//! Each chunk lives at
//! `<data_dir>/chunks/<aa>/<full-64-hex-address>.chunk` where `<aa>`
//! is the first two hex characters of the chunk's 32-byte BLAKE3
//! content address. This matches Autonomi's on-disk shard convention
//! so a future v1.1 push-to-network is a straight `for chunk in
//! store: autonomi.put(chunk.address, chunk.bytes)`.
//!
//! All chunk files are mode 0600; the per-shard directories are
//! mode 0700. Writes are atomic: write-to-`.tmp`, fsync, rename.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use vitonomi_core::protocol::autonomi_bridge::ChunkAddress;

use crate::state_dir;

/// Return `<data_dir>/chunks/<aa>/<full-hex-address>.chunk`. Pure
/// function; does NOT create the parent directory.
#[must_use]
pub fn chunk_path(data_dir: &Path, address: &ChunkAddress) -> PathBuf {
    let hex = hex_encode_32(&address.0);
    let shard = &hex[..2];
    state_dir::chunks_dir(data_dir)
        .join(shard)
        .join(format!("{hex}.chunk"))
}

/// Lowercase-hex of a 32-byte address. Inlined to avoid pulling
/// `hex` into the vault crate's direct dep list.
fn hex_encode_32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Atomically write `bytes` to the chunk's path. Creates the
/// per-shard directory at mode 0700 if missing; writes the chunk
/// file at mode 0600.
///
/// # Errors
///
/// Any filesystem error.
pub fn write_chunk(data_dir: &Path, address: &ChunkAddress, bytes: &[u8]) -> Result<()> {
    let path = chunk_path(data_dir, address);
    let parent = path
        .parent()
        .context("chunk path missing parent directory")?;
    if !parent.exists() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create shard dir {}", parent.display()))?;
        fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", parent.display()))?;
    }
    let tmp = path.with_extension("chunk.tmp");
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read a chunk by address. Returns `None` if the file does not
/// exist; surfaces I/O errors for everything else.
///
/// # Errors
///
/// Any filesystem error other than "not found".
pub fn read_chunk(data_dir: &Path, address: &ChunkAddress) -> Result<Option<Vec<u8>>> {
    let path = chunk_path(data_dir, address);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Delete the chunk file. No-op if missing.
///
/// # Errors
///
/// Any filesystem error other than "not found".
pub fn delete_chunk(data_dir: &Path, address: &ChunkAddress) -> Result<()> {
    let path = chunk_path(data_dir, address);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_addr(byte: u8) -> ChunkAddress {
        ChunkAddress([byte; 32])
    }

    #[test]
    fn chunk_path_is_sharded_by_first_two_hex_chars() {
        let dir = std::path::PathBuf::from("/tmp/some-vault");
        let addr = ChunkAddress([0xab; 32]);
        let p = chunk_path(&dir, &addr);
        assert_eq!(
            p,
            dir.join("chunks")
                .join("ab")
                .join(format!("{}.chunk", "ab".repeat(32))),
        );
    }

    #[test]
    fn write_and_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        crate::state_dir::ensure_data_dir(dir.path()).unwrap();
        let addr = fake_addr(7);
        let payload = b"some chunk bytes".to_vec();
        write_chunk(dir.path(), &addr, &payload).unwrap();
        let got = read_chunk(dir.path(), &addr).unwrap().expect("present");
        assert_eq!(got, payload);
    }

    #[test]
    fn read_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        crate::state_dir::ensure_data_dir(dir.path()).unwrap();
        let addr = fake_addr(7);
        let got = read_chunk(dir.path(), &addr).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        crate::state_dir::ensure_data_dir(dir.path()).unwrap();
        let addr = fake_addr(7);
        // delete missing is fine
        delete_chunk(dir.path(), &addr).unwrap();
        // write + delete
        write_chunk(dir.path(), &addr, b"x").unwrap();
        delete_chunk(dir.path(), &addr).unwrap();
        // and now missing again
        assert!(read_chunk(dir.path(), &addr).unwrap().is_none());
    }

    #[test]
    fn chunk_file_is_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        crate::state_dir::ensure_data_dir(dir.path()).unwrap();
        let addr = fake_addr(7);
        write_chunk(dir.path(), &addr, b"x").unwrap();
        let path = chunk_path(dir.path(), &addr);
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "chunk file must be 0600, got {mode:#o}");
    }

    #[test]
    fn shard_dir_is_mode_0700() {
        let dir = tempfile::tempdir().unwrap();
        crate::state_dir::ensure_data_dir(dir.path()).unwrap();
        let addr = fake_addr(0xab);
        write_chunk(dir.path(), &addr, b"x").unwrap();
        let shard = state_dir::chunks_dir(dir.path()).join("ab");
        let meta = std::fs::metadata(&shard).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "shard dir must be 0700, got {mode:#o}");
    }
}
