//! Vault chunk-storage abstraction.
//!
//! A `VaultStorage` is a content-addressed object store of
//! Autonomi-format chunks (see `crypto::selfencrypt`). Implementations:
//!
//! - `SqliteVaultStorage` — production, persisted in
//!   `<data_dir>/chunks/` + `<data_dir>/index.sqlite`. Lives in
//!   `vitonomi-vault`.
//! - [`crate::protocol::testing::in_memory_storage::InMemoryVaultStorage`]
//!   — test fixture.
//!
//! The trait operates on raw Autonomi-format bytes: callers always
//! pass the exact bytes upstream `self_encryption::encrypt` produced,
//! and the storage layer indexes them by their BLAKE3 content
//! address. Per the encryption boundary, this trait performs **no**
//! cryptography itself — it only verifies that
//! `blake3(bytes) == address` on `put_chunk` (a defence-in-depth
//! check against a buggy or malicious caller). All AEAD + signing
//! happens client-side.
//!
//! Ownership: every chunk is recorded against a `UserId` so the
//! vault can enforce per-user quotas at the storage boundary (Phase
//! 9 / quota enforcement; this milestone only tracks usage). A
//! chunk written by user A then submitted by user B is recorded
//! under whichever owner reaches the store first — content-
//! addressing means the bytes are identical anyway. A future
//! milestone may reference-count chunks across owners.

use async_trait::async_trait;

use crate::errors::CoreError;
use crate::protocol::autonomi_bridge::ChunkAddress;
use crate::types::UserId;

/// Owner-attributed chunk-store operations.
#[async_trait]
pub trait VaultStorage: Send + Sync {
    /// Store a chunk under the given owner. Implementations MUST
    /// verify `blake3(bytes) == address` before persistence and
    /// return `CoreError::Storage(StorageError::AddressMismatch)`
    /// on mismatch.
    ///
    /// Idempotent on `(address, owner)`: re-submitting the same
    /// content under the same owner is a no-op success.
    async fn put_chunk(
        &self,
        owner: UserId,
        address: ChunkAddress,
        bytes: Vec<u8>,
    ) -> Result<(), CoreError>;

    /// Fetch a chunk by address. Returns `CoreError::Storage(
    /// StorageError::NotFound)` if the address is unknown.
    async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError>;

    /// Existence check (cheap; index-only).
    async fn has_chunk(&self, address: &ChunkAddress) -> Result<bool, CoreError>;

    /// Sum of stored chunk sizes attributed to `owner`. Used by the
    /// quota enforcer (Phase 9).
    async fn usage_by_user(&self, owner: UserId) -> Result<u64, CoreError>;

    /// List every chunk address attributed to `owner`. Linear in the
    /// number of chunks the owner has stored — for compaction +
    /// listing flows.
    async fn list_chunks_for_owner(&self, owner: UserId) -> Result<Vec<ChunkAddress>, CoreError>;

    /// Delete a chunk. The vault MUST verify that `owner` matches the
    /// recorded owner of the chunk; otherwise return
    /// `CoreError::Storage(StorageError::OwnerMismatch)`.
    /// `NotFound` for unknown addresses.
    async fn delete_chunk(&self, owner: UserId, address: &ChunkAddress) -> Result<(), CoreError>;
}
