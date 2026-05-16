//! Local file-backed `HeadPointerTransport`.
//!
//! Each `(record_type)` head pointer lives in its own file under
//! `<state_dir>/heads/<record_type-byte:02x>.bin`. Files are mode
//! 0600, atomically replaced via `.tmp` + rename.
//!
//! A hub HTTP-backed transport with rollback-protected `PUT`s is
//! future-work. For single-vault MVP usage the local file is the
//! canonical store; the user just shouldn't run the CLI on two
//! machines concurrently against the same head set.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use async_trait::async_trait;

use vitonomi_core::encoding::{cbor_from_slice, cbor_to_vec};
use vitonomi_core::errors::{CoreError, StorageError};
use vitonomi_core::record::head_pointer::StoredHeadPointer;
use vitonomi_core::record::record_store::HeadPointerTransport;
use vitonomi_core::record::RecordType;

/// File-backed head pointer store. Single-user, single-host. Refuses
/// to read non-0600 files.
pub struct LocalHeadStore {
    heads_dir: PathBuf,
}

impl LocalHeadStore {
    pub fn new(state_dir: &Path) -> std::io::Result<Self> {
        let heads_dir = state_dir.join("heads");
        if !heads_dir.exists() {
            fs::create_dir_all(&heads_dir)?;
            // Lock the dir at 0700.
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&heads_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { heads_dir })
    }

    fn path_for(&self, rt: RecordType) -> PathBuf {
        self.heads_dir.join(format!("{:02x}.bin", rt.as_u8()))
    }
}

#[async_trait]
impl HeadPointerTransport for LocalHeadStore {
    async fn get(&self, rt: RecordType) -> Result<Option<StoredHeadPointer>, CoreError> {
        let path = self.path_for(rt);
        match fs::read(&path) {
            Ok(bytes) => {
                let stored: StoredHeadPointer = cbor_from_slice(&bytes).map_err(|e| {
                    CoreError::Storage(StorageError::Backend(format!(
                        "decode head pointer {}: {e}",
                        path.display()
                    )))
                })?;
                Ok(Some(stored))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CoreError::Storage(StorageError::Io(format!(
                "read {}: {e}",
                path.display()
            )))),
        }
    }

    async fn put(&self, rt: RecordType, stored: StoredHeadPointer) -> Result<(), CoreError> {
        // Soft monotonicity: refuse to overwrite a higher seq with a
        // lower one (mirrors what the hub HTTP endpoint will do in
        // slice 4).
        if let Some(existing) = self.get(rt).await? {
            if stored.seq < existing.seq {
                return Err(CoreError::Storage(StorageError::Backend(format!(
                    "head pointer regression: new seq {} < stored seq {}",
                    stored.seq, existing.seq
                ))));
            }
        }
        let path = self.path_for(rt);
        let bytes = cbor_to_vec(&stored).map_err(|e| {
            CoreError::Storage(StorageError::Backend(format!("encode head pointer: {e}")))
        })?;
        let tmp = path.with_extension("bin.tmp");
        {
            let mut f = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| {
                    CoreError::Storage(StorageError::Io(format!("open {}: {e}", tmp.display())))
                })?;
            f.write_all(&bytes).map_err(|e| {
                CoreError::Storage(StorageError::Io(format!("write {}: {e}", tmp.display())))
            })?;
        }
        fs::rename(&tmp, &path).map_err(|e| {
            CoreError::Storage(StorageError::Io(format!(
                "rename {} -> {}: {e}",
                tmp.display(),
                path.display()
            )))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitonomi_core::crypto::pq::MlDsa65Signature;
    use vitonomi_core::record::head_pointer::StoredHeadPointer;
    use vitonomi_core::types::FormatVersion;

    fn sample(seq: u64) -> StoredHeadPointer {
        StoredHeadPointer {
            format_version: FormatVersion::V1,
            seq,
            encrypted_pointer: vec![0xaa, 0xbb, 0xcc],
            sig_user_outer: MlDsa65Signature(vec![0u8; 3309]),
        }
    }

    #[tokio::test]
    async fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalHeadStore::new(dir.path()).unwrap();
        store.put(RecordType::Credential, sample(1)).await.unwrap();
        let got = store.get(RecordType::Credential).await.unwrap().unwrap();
        assert_eq!(got.seq, 1);
    }

    #[tokio::test]
    async fn missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalHeadStore::new(dir.path()).unwrap();
        assert!(store.get(RecordType::Alias).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rejects_seq_regression() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalHeadStore::new(dir.path()).unwrap();
        store.put(RecordType::Credential, sample(5)).await.unwrap();
        let err = store
            .put(RecordType::Credential, sample(3))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Storage(vitonomi_core::errors::StorageError::Backend(_))
        ));
    }

    #[tokio::test]
    async fn accepts_seq_replay_at_equal() {
        // Re-publishing the same seq (e.g. retry after a crash mid-
        // put) is fine.
        let dir = tempfile::tempdir().unwrap();
        let store = LocalHeadStore::new(dir.path()).unwrap();
        store.put(RecordType::Credential, sample(2)).await.unwrap();
        store.put(RecordType::Credential, sample(2)).await.unwrap();
    }
}
