//! `SqliteVaultStorage` — the production `VaultStorage` impl.
//!
//! Chunk metadata lives in `<data_dir>/index.sqlite`; chunk bytes
//! live on the filesystem under `<data_dir>/chunks/`. Splitting the
//! large chunk bytes out of SQLite keeps the database compact and
//! lets the DB always serve `has_chunk` / `usage_by_user` /
//! `list_chunks_for_owner` from the index without touching disk.
//!
//! Behaviour invariants:
//!
//! 1. `put_chunk` verifies `blake3(bytes) == address` before
//!    persisting. Mismatch → `StorageError::AddressMismatch`.
//! 2. `put_chunk` is idempotent on `(address, owner)`. If the
//!    address already exists under a different owner, the original
//!    owner is kept (content-addressing means the bytes are
//!    identical) — matches the in-memory test fixture's semantics.
//! 3. `delete_chunk` requires owner match; mismatched → typed
//!    `StorageError::OwnerMismatch`.
//! 4. Writes are atomic at both layers: filesystem write goes
//!    through a `.tmp` + rename, SQLite uses `INSERT OR IGNORE`
//!    inside an implicit transaction. If the FS write succeeds but
//!    the DB insert fails, the orphan chunk file is harmless (a
//!    later put with the same address re-indexes it; or
//!    compaction in v1.1 garbage-collects).

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{ConnectOptions as _, Pool, Sqlite};

use vitonomi_core::crypto::selfencrypt::verify_chunk_address;
use vitonomi_core::errors::{CoreError, StorageError};
use vitonomi_core::protocol::autonomi_bridge::ChunkAddress;
use vitonomi_core::protocol::vault_storage::VaultStorage;
use vitonomi_core::types::UserId;

use crate::state_dir;
use crate::storage::fs_chunk_dir;

/// SQLite-backed chunk store. Cheaply cloneable: the inner pool is
/// `Arc`-wrapped so multiple async tasks can share one instance.
#[derive(Clone)]
pub struct SqliteVaultStorage {
    pool: Pool<Sqlite>,
    data_dir: PathBuf,
}

impl SqliteVaultStorage {
    /// Open (or create) the chunk store at `<data_dir>/index.sqlite`.
    /// Creates `<data_dir>/chunks/` as a side effect if missing.
    ///
    /// # Errors
    ///
    /// Filesystem / SQL errors.
    pub async fn open(data_dir: &Path) -> anyhow::Result<Self> {
        // Ensure the chunks/ directory exists at 0700 BEFORE opening
        // the DB. `state_dir::ensure_data_dir` already does this for
        // `chunks/`, but `SqliteVaultStorage::open` may be called
        // independently of the daemon's bootstrap path.
        state_dir::ensure_data_dir(data_dir)?;
        let db_path = state_dir::chunk_index_db(data_dir);

        // `create_if_missing(true)` lets a fresh vault stand up
        // without a separate init step.
        let mut connect_opts = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        connect_opts = connect_opts.disable_statement_logging();

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(connect_opts)
            .await?;

        // Schema migration. Single table; we manage the
        // schema-version row by hand so we don't need sqlx-migrate.
        sqlx::query(SCHEMA_V1)
            .execute(&pool)
            .await
            .map_err(|e| anyhow::anyhow!("create chunks table: {e}"))?;

        // Lock the DB file at 0600 once it exists.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(meta) = std::fs::metadata(&db_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&db_path, perms);
            }
        }

        Ok(Self {
            pool,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// Underlying pool — exposed for tests.
    #[cfg(test)]
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }
}

/// Schema as of slice 2. Bump `schema_version` if a future slice
/// changes the layout. `INSERT OR IGNORE` keeps the migration
/// idempotent on a re-open.
const SCHEMA_V1: &str = r"
CREATE TABLE IF NOT EXISTS chunks (
    address               BLOB PRIMARY KEY NOT NULL,
    owner_user_id         BLOB NOT NULL,
    size                  INTEGER NOT NULL,
    created_at_ms         INTEGER NOT NULL,
    replicated_to_peers   INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_chunks_owner ON chunks (owner_user_id);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

INSERT OR IGNORE INTO schema_version (version) VALUES (1);
";

#[async_trait]
impl VaultStorage for SqliteVaultStorage {
    async fn put_chunk(
        &self,
        owner: UserId,
        address: ChunkAddress,
        bytes: Vec<u8>,
    ) -> Result<(), CoreError> {
        // Defence in depth: the relay-bus handler ALSO verifies this,
        // but the storage layer is the final authority — a bug or
        // malicious internal caller can't bypass it here.
        verify_chunk_address(&address, &bytes).map_err(CoreError::from)?;

        // Idempotent: INSERT OR IGNORE keeps the first-recorded owner
        // if the address is already present.
        let now_ms = current_ms();
        let size = bytes.len() as i64;
        let inserted = sqlx::query(
            r"INSERT OR IGNORE INTO chunks
              (address, owner_user_id, size, created_at_ms, replicated_to_peers)
              VALUES (?, ?, ?, ?, 0)",
        )
        .bind(&address.0[..])
        .bind(&owner.0[..])
        .bind(size)
        .bind(now_ms)
        .execute(&self.pool)
        .await
        .map_err(sql_err)?
        .rows_affected();

        // If a row was inserted, we're a fresh chunk → write to FS.
        // If the row existed already we still re-write the FS copy
        // if missing (e.g., FS corruption recovery). Otherwise we
        // skip the write entirely — the bytes are content-addressed
        // so any existing file is correct.
        if inserted == 1 {
            fs_chunk_dir::write_chunk(&self.data_dir, &address, &bytes)
                .map_err(|e| CoreError::Storage(StorageError::Io(e.to_string())))?;
        } else {
            // No row inserted because the chunk already existed.
            // Self-heal a missing FS copy if needed.
            let path = fs_chunk_dir::chunk_path(&self.data_dir, &address);
            if !path.exists() {
                fs_chunk_dir::write_chunk(&self.data_dir, &address, &bytes)
                    .map_err(|e| CoreError::Storage(StorageError::Io(e.to_string())))?;
            }
        }
        Ok(())
    }

    async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError> {
        // Existence check via the index first — avoids a stat() for
        // chunks we definitely don't have.
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT address FROM chunks WHERE address = ? LIMIT 1")
                .bind(&address.0[..])
                .fetch_optional(&self.pool)
                .await
                .map_err(sql_err)?;
        if row.is_none() {
            return Err(CoreError::Storage(StorageError::NotFound));
        }
        let bytes = fs_chunk_dir::read_chunk(&self.data_dir, address)
            .map_err(|e| CoreError::Storage(StorageError::Io(e.to_string())))?;
        bytes.ok_or(CoreError::Storage(StorageError::NotFound))
    }

    async fn has_chunk(&self, address: &ChunkAddress) -> Result<bool, CoreError> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT address FROM chunks WHERE address = ? LIMIT 1")
                .bind(&address.0[..])
                .fetch_optional(&self.pool)
                .await
                .map_err(sql_err)?;
        Ok(row.is_some())
    }

    async fn usage_by_user(&self, owner: UserId) -> Result<u64, CoreError> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT COALESCE(SUM(size), 0) FROM chunks WHERE owner_user_id = ?")
                .bind(&owner.0[..])
                .fetch_optional(&self.pool)
                .await
                .map_err(sql_err)?;
        Ok(row.map(|(n,)| n.max(0) as u64).unwrap_or(0))
    }

    async fn list_chunks_for_owner(&self, owner: UserId) -> Result<Vec<ChunkAddress>, CoreError> {
        let rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT address FROM chunks WHERE owner_user_id = ? ORDER BY address")
                .bind(&owner.0[..])
                .fetch_all(&self.pool)
                .await
                .map_err(sql_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for (addr_bytes,) in rows {
            let arr: [u8; 32] = addr_bytes.as_slice().try_into().map_err(|_| {
                CoreError::Storage(StorageError::Backend(format!(
                    "address column has wrong length {}",
                    addr_bytes.len()
                )))
            })?;
            out.push(ChunkAddress(arr));
        }
        Ok(out)
    }

    async fn delete_chunk(&self, owner: UserId, address: &ChunkAddress) -> Result<(), CoreError> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT owner_user_id FROM chunks WHERE address = ?")
                .bind(&address.0[..])
                .fetch_optional(&self.pool)
                .await
                .map_err(sql_err)?;
        let Some((current_owner,)) = row else {
            return Err(CoreError::Storage(StorageError::NotFound));
        };
        if current_owner.as_slice() != owner.0.as_slice() {
            return Err(CoreError::Storage(StorageError::OwnerMismatch));
        }
        sqlx::query("DELETE FROM chunks WHERE address = ?")
            .bind(&address.0[..])
            .execute(&self.pool)
            .await
            .map_err(sql_err)?;
        fs_chunk_dir::delete_chunk(&self.data_dir, address)
            .map_err(|e| CoreError::Storage(StorageError::Io(e.to_string())))?;
        Ok(())
    }
}

fn current_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_millis() as i64
}

fn sql_err(e: sqlx::Error) -> CoreError {
    CoreError::Storage(StorageError::Backend(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitonomi_core::crypto::selfencrypt::encrypt;

    fn user(byte: u8) -> UserId {
        UserId([byte; 16])
    }

    fn sample_chunks() -> (
        Vec<vitonomi_core::crypto::selfencrypt::Chunk>,
        vitonomi_core::crypto::selfencrypt::DataMap,
    ) {
        let bytes: Vec<u8> = (0..(8 * 1024)).map(|i| (i & 0xff) as u8).collect();
        encrypt(&bytes).unwrap()
    }

    async fn fresh_store() -> (tempfile::TempDir, SqliteVaultStorage) {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteVaultStorage::open(dir.path()).await.unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn put_get_round_trip() {
        let (_dir, store) = fresh_store().await;
        let (chunks, _) = sample_chunks();
        for c in &chunks {
            store
                .put_chunk(user(1), c.address.clone(), c.bytes.clone())
                .await
                .unwrap();
        }
        for c in &chunks {
            assert!(store.has_chunk(&c.address).await.unwrap());
            let got = store.get_chunk(&c.address).await.unwrap();
            assert_eq!(got, c.bytes);
        }
    }

    #[tokio::test]
    async fn put_rejects_mismatched_address_blake3() {
        let (_dir, store) = fresh_store().await;
        let bad_addr = ChunkAddress([7u8; 32]);
        let bad_bytes = vec![1u8, 2, 3, 4, 5];
        let err = store
            .put_chunk(user(1), bad_addr, bad_bytes)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Storage(StorageError::AddressMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn put_idempotent_same_owner() {
        let (_dir, store) = fresh_store().await;
        let (chunks, _) = sample_chunks();
        let c = &chunks[0];
        store
            .put_chunk(user(1), c.address.clone(), c.bytes.clone())
            .await
            .unwrap();
        // Re-put under same owner is a no-op success.
        store
            .put_chunk(user(1), c.address.clone(), c.bytes.clone())
            .await
            .unwrap();
        // Usage didn't double.
        assert_eq!(
            store.usage_by_user(user(1)).await.unwrap(),
            c.bytes.len() as u64
        );
    }

    #[tokio::test]
    async fn put_different_owner_keeps_first_owner() {
        // Content-addressing: identical bytes from a second user are
        // already in the store. The first owner stays attributed.
        let (_dir, store) = fresh_store().await;
        let (chunks, _) = sample_chunks();
        let c = &chunks[0];
        store
            .put_chunk(user(1), c.address.clone(), c.bytes.clone())
            .await
            .unwrap();
        store
            .put_chunk(user(2), c.address.clone(), c.bytes.clone())
            .await
            .unwrap();
        // Usage only counts under user 1.
        assert_eq!(
            store.usage_by_user(user(1)).await.unwrap(),
            c.bytes.len() as u64
        );
        assert_eq!(store.usage_by_user(user(2)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn usage_by_user_sums_correctly() {
        let (_dir, store) = fresh_store().await;
        let (chunks, _) = sample_chunks();
        let mut expected: u64 = 0;
        for c in &chunks {
            expected += c.bytes.len() as u64;
            store
                .put_chunk(user(1), c.address.clone(), c.bytes.clone())
                .await
                .unwrap();
        }
        assert_eq!(store.usage_by_user(user(1)).await.unwrap(), expected);
        assert_eq!(store.usage_by_user(user(2)).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn list_chunks_for_owner_returns_only_own() {
        let (_dir, store) = fresh_store().await;
        let (chunks, _) = sample_chunks();
        let mid = chunks.len() / 2;
        for c in &chunks[..mid] {
            store
                .put_chunk(user(1), c.address.clone(), c.bytes.clone())
                .await
                .unwrap();
        }
        for c in &chunks[mid..] {
            store
                .put_chunk(user(2), c.address.clone(), c.bytes.clone())
                .await
                .unwrap();
        }
        let u1 = store.list_chunks_for_owner(user(1)).await.unwrap();
        let u2 = store.list_chunks_for_owner(user(2)).await.unwrap();
        assert_eq!(u1.len(), mid);
        assert_eq!(u2.len(), chunks.len() - mid);
        // Sets should be disjoint.
        let s1: std::collections::HashSet<_> = u1.iter().map(|a| a.0).collect();
        let s2: std::collections::HashSet<_> = u2.iter().map(|a| a.0).collect();
        assert!(s1.is_disjoint(&s2));
    }

    #[tokio::test]
    async fn delete_chunk_requires_owner_match() {
        let (_dir, store) = fresh_store().await;
        let (chunks, _) = sample_chunks();
        let c = &chunks[0];
        store
            .put_chunk(user(1), c.address.clone(), c.bytes.clone())
            .await
            .unwrap();
        // Wrong owner — must fail typed.
        let err = store.delete_chunk(user(2), &c.address).await.unwrap_err();
        assert!(matches!(
            err,
            CoreError::Storage(StorageError::OwnerMismatch)
        ));
        // Correct owner — succeeds.
        store.delete_chunk(user(1), &c.address).await.unwrap();
        assert!(!store.has_chunk(&c.address).await.unwrap());
        // File is gone from disk.
        let p = fs_chunk_dir::chunk_path(store.data_dir.as_path(), &c.address);
        assert!(!p.exists(), "chunk file should be removed from disk");
    }

    #[tokio::test]
    async fn delete_chunk_not_found_typed() {
        let (_dir, store) = fresh_store().await;
        let err = store
            .delete_chunk(user(1), &ChunkAddress([0u8; 32]))
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Storage(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn get_chunk_not_found_typed() {
        let (_dir, store) = fresh_store().await;
        let err = store.get_chunk(&ChunkAddress([0u8; 32])).await.unwrap_err();
        assert!(matches!(err, CoreError::Storage(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn chunks_persist_across_pool_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (chunks, _) = sample_chunks();
        // First open: write everything, then drop.
        {
            let store = SqliteVaultStorage::open(dir.path()).await.unwrap();
            for c in &chunks {
                store
                    .put_chunk(user(1), c.address.clone(), c.bytes.clone())
                    .await
                    .unwrap();
            }
            store.pool.close().await;
        }
        // Second open: same data dir, everything still there.
        let store = SqliteVaultStorage::open(dir.path()).await.unwrap();
        for c in &chunks {
            assert!(store.has_chunk(&c.address).await.unwrap());
            let got = store.get_chunk(&c.address).await.unwrap();
            assert_eq!(got, c.bytes);
        }
    }

    #[tokio::test]
    async fn chunk_dir_is_sharded_by_first_two_hex_chars() {
        let (_dir, store) = fresh_store().await;
        let (chunks, _) = sample_chunks();
        for c in &chunks {
            store
                .put_chunk(user(1), c.address.clone(), c.bytes.clone())
                .await
                .unwrap();
        }
        // Each chunk lives at chunks/<aa>/<full>.chunk.
        for c in &chunks {
            let expected = fs_chunk_dir::chunk_path(store.data_dir.as_path(), &c.address);
            assert!(expected.exists(), "{} missing", expected.display());
            // Verify the shard component is exactly two hex chars and
            // matches the address prefix.
            let mut comps: Vec<_> = expected
                .components()
                .rev()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            comps.reverse();
            let shard = comps[comps.len() - 2].clone();
            assert_eq!(shard.len(), 2);
            assert!(shard.chars().all(|ch| ch.is_ascii_hexdigit()));
            let address_hex_prefix: String = c
                .address
                .0
                .iter()
                .take(1)
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(shard, address_hex_prefix);
        }
    }
}
