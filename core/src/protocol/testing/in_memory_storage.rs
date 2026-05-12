//! In-memory `VaultStorage` for tests and prototyping.
//!
//! Matches the production semantics of `SqliteVaultStorage` (lives in
//! `vitonomi-vault`): same address-verification on put, same
//! owner-mismatch rejection on delete, same usage accounting. The
//! production conformance suite (slice 2) exercises both impls
//! against the same trait contract.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::crypto::selfencrypt::verify_chunk_address;
use crate::errors::{CoreError, StorageError};
use crate::protocol::autonomi_bridge::ChunkAddress;
use crate::protocol::vault_storage::VaultStorage;
use crate::types::UserId;

struct Entry {
    owner: UserId,
    bytes: Vec<u8>,
}

#[derive(Default)]
pub struct InMemoryVaultStorage {
    chunks: Mutex<HashMap<[u8; 32], Entry>>,
}

impl InMemoryVaultStorage {
    #[must_use]
    pub fn new() -> Self {
        Self {
            chunks: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl VaultStorage for InMemoryVaultStorage {
    async fn put_chunk(
        &self,
        owner: UserId,
        address: ChunkAddress,
        bytes: Vec<u8>,
    ) -> Result<(), CoreError> {
        verify_chunk_address(&address, &bytes).map_err(CoreError::from)?;
        let mut guard = self
            .chunks
            .lock()
            .map_err(|_| CoreError::Storage(StorageError::Backend("mutex poisoned".into())))?;
        // Idempotent on (address, owner). If the address exists under
        // a different owner, content-addressing guarantees the bytes
        // are identical — keep the first recorded owner.
        guard.entry(address.0).or_insert(Entry { owner, bytes });
        Ok(())
    }

    async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError> {
        let guard = self
            .chunks
            .lock()
            .map_err(|_| CoreError::Storage(StorageError::Backend("mutex poisoned".into())))?;
        guard
            .get(&address.0)
            .map(|e| e.bytes.clone())
            .ok_or(CoreError::Storage(StorageError::NotFound))
    }

    async fn has_chunk(&self, address: &ChunkAddress) -> Result<bool, CoreError> {
        let guard = self
            .chunks
            .lock()
            .map_err(|_| CoreError::Storage(StorageError::Backend("mutex poisoned".into())))?;
        Ok(guard.contains_key(&address.0))
    }

    async fn usage_by_user(&self, owner: UserId) -> Result<u64, CoreError> {
        let guard = self
            .chunks
            .lock()
            .map_err(|_| CoreError::Storage(StorageError::Backend("mutex poisoned".into())))?;
        let total: u64 = guard
            .values()
            .filter(|e| e.owner.0 == owner.0)
            .map(|e| e.bytes.len() as u64)
            .sum();
        Ok(total)
    }

    async fn list_chunks_for_owner(&self, owner: UserId) -> Result<Vec<ChunkAddress>, CoreError> {
        let guard = self
            .chunks
            .lock()
            .map_err(|_| CoreError::Storage(StorageError::Backend("mutex poisoned".into())))?;
        let mut out: Vec<_> = guard
            .iter()
            .filter(|(_, e)| e.owner.0 == owner.0)
            .map(|(addr, _)| ChunkAddress(*addr))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    async fn delete_chunk(&self, owner: UserId, address: &ChunkAddress) -> Result<(), CoreError> {
        let mut guard = self
            .chunks
            .lock()
            .map_err(|_| CoreError::Storage(StorageError::Backend("mutex poisoned".into())))?;
        match guard.get(&address.0) {
            None => Err(CoreError::Storage(StorageError::NotFound)),
            Some(entry) if entry.owner.0 != owner.0 => {
                Err(CoreError::Storage(StorageError::OwnerMismatch))
            }
            Some(_) => {
                guard.remove(&address.0);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::selfencrypt::encrypt;

    fn user(byte: u8) -> UserId {
        UserId([byte; 16])
    }

    fn sample_chunks() -> (
        Vec<crate::crypto::selfencrypt::Chunk>,
        crate::crypto::selfencrypt::DataMap,
    ) {
        let bytes: Vec<u8> = (0..(8 * 1024)).map(|i| (i & 0xff) as u8).collect();
        encrypt(&bytes).unwrap()
    }

    #[tokio::test]
    async fn round_trip() {
        let store = InMemoryVaultStorage::new();
        let (chunks, _) = sample_chunks();
        for c in &chunks {
            store
                .put_chunk(user(1), c.address.clone(), c.bytes.clone())
                .await
                .unwrap();
        }
        for c in &chunks {
            let got = store.get_chunk(&c.address).await.unwrap();
            assert_eq!(got, c.bytes);
            assert!(store.has_chunk(&c.address).await.unwrap());
        }
    }

    #[tokio::test]
    async fn put_rejects_address_mismatch() {
        let store = InMemoryVaultStorage::new();
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
        let store = InMemoryVaultStorage::new();
        let (chunks, _) = sample_chunks();
        let c = &chunks[0];
        store
            .put_chunk(user(1), c.address.clone(), c.bytes.clone())
            .await
            .unwrap();
        // Second put under the same owner succeeds (no-op).
        store
            .put_chunk(user(1), c.address.clone(), c.bytes.clone())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn usage_by_user_sums_correctly() {
        let store = InMemoryVaultStorage::new();
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
    async fn list_chunks_for_owner_filters() {
        let store = InMemoryVaultStorage::new();
        let (chunks, _) = sample_chunks();
        // Put first half under user 1, second half under user 2.
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
    }

    #[tokio::test]
    async fn delete_requires_owner_match() {
        let store = InMemoryVaultStorage::new();
        let (chunks, _) = sample_chunks();
        let c = &chunks[0];
        store
            .put_chunk(user(1), c.address.clone(), c.bytes.clone())
            .await
            .unwrap();
        let err = store.delete_chunk(user(2), &c.address).await.unwrap_err();
        assert!(matches!(
            err,
            CoreError::Storage(StorageError::OwnerMismatch)
        ));
        store.delete_chunk(user(1), &c.address).await.unwrap();
        assert!(!store.has_chunk(&c.address).await.unwrap());
    }

    #[tokio::test]
    async fn get_unknown_returns_not_found() {
        let store = InMemoryVaultStorage::new();
        let err = store.get_chunk(&ChunkAddress([0u8; 32])).await.unwrap_err();
        assert!(matches!(err, CoreError::Storage(StorageError::NotFound)));
    }
}
