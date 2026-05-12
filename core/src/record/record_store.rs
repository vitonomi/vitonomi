//! High-level client API on top of the chunk store + snapshot chain
//! + head pointer.
//!
//! Transport-agnostic: `RecordStore` is parameterised over a
//! [`ChunkTransport`] and a [`HeadPointerTransport`]. Slice 1 wires
//! it to in-memory implementations of both for round-trip tests;
//! Slice 3 swaps the chunk transport for a libp2p data-plane
//! client, and Slice 4 swaps the head-pointer transport for a hub
//! HTTP client.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::crypto::aead::{open as aead_open, seal as aead_seal};
use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65SecretKey};
use crate::crypto::selfencrypt::{decrypt as se_decrypt, encrypt as se_encrypt, Chunk};
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::{CoreError, CryptoError};
use crate::protocol::autonomi_bridge::ChunkAddress;
use crate::record::head_pointer::{open_head_pointer, seal_head_pointer, StoredHeadPointer};
use crate::record::snapshot::{
    sign_snapshot, snapshot_aad, verify_snapshot, RecordFrame, RecordOp, SignedSnapshot, Snapshot,
};
use crate::record::user_keys::{
    derive_head_pointer_aead_key, derive_record_aead_key, UserAeadMaster,
};
use crate::record::{BackupTarget, RecordId, RecordType};
use crate::types::{ClusterId, FormatVersion, UserId};

/// Everything a `RecordStore` needs to do crypto on the client side.
#[derive(Clone)]
pub struct UserKeys {
    pub user_id: UserId,
    pub cluster_id: ClusterId,
    pub identity_pk: MlDsa65PublicKey,
    pub identity_sk: MlDsa65SecretKey,
    pub user_aead_master: UserAeadMaster,
}

/// Transport-agnostic chunk store seen by the client. Slice 1 backs
/// it with an in-memory map; Slice 3 backs it with libp2p
/// request-response. The trait surface is intentionally small:
/// content-addressed put + content-addressed get. Authentication +
/// ownership attribution happen one layer up (libp2p auth +
/// per-request signatures).
#[async_trait]
pub trait ChunkTransport: Send + Sync {
    async fn put_chunks(&self, chunks: &[Chunk]) -> Result<(), CoreError>;
    async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError>;
}

/// Head-pointer storage as seen by the client. Slice 1 backs it with
/// an in-memory map; Slice 3/4 swap to hub HTTP.
#[async_trait]
pub trait HeadPointerTransport: Send + Sync {
    async fn get(&self, record_type: RecordType) -> Result<Option<StoredHeadPointer>, CoreError>;
    async fn put(
        &self,
        record_type: RecordType,
        stored: StoredHeadPointer,
    ) -> Result<(), CoreError>;
}

/// Client-side record store. Owns the user's keys and stitches the
/// chunk + head pointer + snapshot chain together.
pub struct RecordStore<C: ChunkTransport, H: HeadPointerTransport> {
    keys: UserKeys,
    chunks: C,
    heads: H,
}

impl<C: ChunkTransport, H: HeadPointerTransport> RecordStore<C, H> {
    pub fn new(keys: UserKeys, chunks: C, heads: H) -> Self {
        Self {
            keys,
            chunks,
            heads,
        }
    }

    /// Insert a new record with random RecordId; returns the id.
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure.
    pub async fn put(&self, rt: RecordType, plaintext: &[u8]) -> Result<RecordId, CoreError> {
        let record_id = RecordId::generate()?;
        self.put_or_replace(rt, record_id, plaintext).await?;
        Ok(record_id)
    }

    /// Insert / overwrite a record with a known RecordId. Useful for
    /// updates after a `list`/`get`.
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure.
    pub async fn put_or_replace(
        &self,
        rt: RecordType,
        record_id: RecordId,
        plaintext: &[u8],
    ) -> Result<(), CoreError> {
        // 1. AEAD-seal plaintext under per-record-type key, then self-
        // encrypt to chunks + DataMap. AAD binds user_id +
        // record_type + record_id.
        let record_key =
            derive_record_aead_key(&self.keys.user_aead_master, self.keys.user_id, rt)?;
        let mut aad = Vec::with_capacity(b"vitonomi/record_payload/v1".len() + 16 + 1 + 16);
        aad.extend_from_slice(b"vitonomi/record_payload/v1");
        aad.extend_from_slice(&self.keys.user_id.0);
        aad.push(rt.as_u8());
        aad.extend_from_slice(&record_id.0);
        let payload_ct = aead_seal(&record_key, plaintext, &aad)?;
        let (payload_chunks, payload_dm) = se_encrypt(&payload_ct).map_err(CoreError::Crypto)?;
        self.chunks.put_chunks(&payload_chunks).await?;

        // 2. Load the previous snapshot (if any) so we can fold the
        // new frame into the cumulative-frames model.
        let prev = self.fetch_signed_head_snapshot(rt).await?;
        let (next_seq, mut frames, prev_address) = match prev {
            Some((signed, head_addr)) => {
                let new_version = signed
                    .snapshot
                    .frames
                    .iter()
                    .find(|f| f.record_id == record_id)
                    .map(|f| f.prev_record_version + 1)
                    .unwrap_or(0);
                // Replace any existing frame for the same id; keep
                // others in their original order.
                let mut frames: Vec<RecordFrame> = signed
                    .snapshot
                    .frames
                    .into_iter()
                    .filter(|f| f.record_id != record_id)
                    .collect();
                frames.push(RecordFrame {
                    record_id,
                    op: RecordOp::Put {
                        payload_data_map: payload_dm,
                    },
                    prev_record_version: new_version,
                });
                (signed.snapshot.seq + 1, frames, Some(head_addr))
            }
            None => (
                0u64,
                vec![RecordFrame {
                    record_id,
                    op: RecordOp::Put {
                        payload_data_map: payload_dm,
                    },
                    prev_record_version: 0,
                }],
                None,
            ),
        };

        // Deterministic frame order: sort by record_id bytes to keep
        // CBOR-encoding stable across snapshots that hold the same
        // logical set.
        frames.sort_by(|a, b| a.record_id.0.cmp(&b.record_id.0));

        // 3. Build, sign, AEAD-seal, self-encrypt the new snapshot.
        self.write_snapshot(rt, next_seq, prev_address, frames)
            .await?;
        Ok(())
    }

    /// Delete a record by id. Appends a tombstone frame.
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure.
    pub async fn delete(&self, rt: RecordType, record_id: RecordId) -> Result<(), CoreError> {
        let prev = self.fetch_signed_head_snapshot(rt).await?;
        let (next_seq, mut frames, prev_address) = match prev {
            Some((signed, head_addr)) => {
                let new_version = signed
                    .snapshot
                    .frames
                    .iter()
                    .find(|f| f.record_id == record_id)
                    .map(|f| f.prev_record_version + 1)
                    .unwrap_or(0);
                let mut frames: Vec<RecordFrame> = signed
                    .snapshot
                    .frames
                    .into_iter()
                    .filter(|f| f.record_id != record_id)
                    .collect();
                frames.push(RecordFrame {
                    record_id,
                    op: RecordOp::Delete,
                    prev_record_version: new_version,
                });
                (signed.snapshot.seq + 1, frames, Some(head_addr))
            }
            None => {
                // Nothing to delete — still create a snapshot to
                // commit the tombstone for future seq monotonicity.
                (
                    0u64,
                    vec![RecordFrame {
                        record_id,
                        op: RecordOp::Delete,
                        prev_record_version: 0,
                    }],
                    None,
                )
            }
        };
        frames.sort_by(|a, b| a.record_id.0.cmp(&b.record_id.0));
        self.write_snapshot(rt, next_seq, prev_address, frames)
            .await?;
        Ok(())
    }

    /// Fetch a single record by id. Returns `None` if the record is
    /// not present (never written or deleted).
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure.
    pub async fn get(
        &self,
        rt: RecordType,
        record_id: RecordId,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let state = self.rebuild_state(rt).await?;
        Ok(state
            .into_iter()
            .find_map(|(id, body)| if id == record_id { Some(body) } else { None }))
    }

    /// List all live (non-deleted) records of `rt`.
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure.
    pub async fn list(&self, rt: RecordType) -> Result<Vec<(RecordId, Vec<u8>)>, CoreError> {
        self.rebuild_state(rt).await
    }

    /// Replay every live frame in the head snapshot into a fully-
    /// decrypted vector of (record_id, plaintext). Used by `get` /
    /// `list` and by the recovery path.
    pub async fn rebuild_state(
        &self,
        rt: RecordType,
    ) -> Result<Vec<(RecordId, Vec<u8>)>, CoreError> {
        let head_opt = self.fetch_signed_head_snapshot(rt).await?;
        let Some((signed, _)) = head_opt else {
            return Ok(Vec::new());
        };

        let record_key =
            derive_record_aead_key(&self.keys.user_aead_master, self.keys.user_id, rt)?;
        let mut out: Vec<(RecordId, Vec<u8>)> = Vec::new();

        for frame in signed.snapshot.frames {
            match frame.op {
                RecordOp::Delete => {}
                RecordOp::Put { payload_data_map } => {
                    // Pre-fetch chunks asynchronously, then drive the
                    // sync selfencrypt::decrypt over an in-memory map.
                    let addrs = payload_data_map
                        .chunk_addresses()
                        .map_err(CoreError::Crypto)?;
                    let cache = self.prefetch_chunks(&addrs).await?;
                    let ct = se_decrypt(&payload_data_map, |addr| {
                        cache
                            .get(&addr.0)
                            .cloned()
                            .ok_or(CoreError::Storage(crate::errors::StorageError::NotFound))
                    })
                    .map_err(CoreError::Crypto)?;
                    let mut aad = Vec::with_capacity(64);
                    aad.extend_from_slice(b"vitonomi/record_payload/v1");
                    aad.extend_from_slice(&self.keys.user_id.0);
                    aad.push(rt.as_u8());
                    aad.extend_from_slice(&frame.record_id.0);
                    let pt = aead_open(&record_key, &ct, &aad)?;
                    out.push((frame.record_id, pt));
                }
            }
        }
        out.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        Ok(out)
    }

    /// Fetch many chunks asynchronously, returning an address →
    /// bytes map. The sync closure inside
    /// [`crate::crypto::selfencrypt::decrypt`] reads from this map.
    async fn prefetch_chunks(
        &self,
        addresses: &[ChunkAddress],
    ) -> Result<HashMap<[u8; 32], Vec<u8>>, CoreError> {
        // Sequential fetch — the libp2p transport will replace this
        // with a parallel pipeline in Slice 3 if profiling motivates
        // it. For Slice 1's in-memory tests sequential is fine.
        let mut out = HashMap::with_capacity(addresses.len());
        for addr in addresses {
            let bytes = self.chunks.get_chunk(addr).await?;
            out.insert(addr.0, bytes);
        }
        Ok(out)
    }

    // ── internals ─────────────────────────────────────────────────

    async fn fetch_signed_head_snapshot(
        &self,
        rt: RecordType,
    ) -> Result<Option<(SignedSnapshot, ChunkAddress)>, CoreError> {
        let Some(stored) = self.heads.get(rt).await? else {
            return Ok(None);
        };
        let head_key =
            derive_head_pointer_aead_key(&self.keys.user_aead_master, self.keys.user_id)?;
        let pointer = open_head_pointer(
            &head_key,
            &self.keys.identity_pk,
            &self.keys.cluster_id,
            &self.keys.user_id,
            rt,
            &stored,
        )?;

        // Fetch + AEAD-open + verify the snapshot referenced by the
        // pointer's data map.
        let dm = pointer.snapshot_data_map.clone();
        let addrs = dm.chunk_addresses().map_err(CoreError::Crypto)?;
        let head_address = addrs
            .first()
            .cloned()
            .ok_or_else(|| CoreError::Crypto(CryptoError::Kdf("empty DataMap".into())))?;
        let cache = self.prefetch_chunks(&addrs).await?;
        let snap_ct = se_decrypt(&dm, |addr| {
            cache
                .get(&addr.0)
                .cloned()
                .ok_or(CoreError::Storage(crate::errors::StorageError::NotFound))
        })
        .map_err(CoreError::Crypto)?;
        let snap_aad = snapshot_aad(self.keys.user_id, rt, pointer.seq);
        let snap_key = derive_record_aead_key(&self.keys.user_aead_master, self.keys.user_id, rt)?;
        let pt = aead_open(&snap_key, &snap_ct, &snap_aad)?;
        let signed: SignedSnapshot = cbor_from_slice(&pt).map_err(CoreError::Protocol)?;
        if signed.snapshot.seq != pointer.seq {
            return Err(CoreError::Crypto(CryptoError::Kdf(format!(
                "snapshot seq {} does not match head pointer seq {}",
                signed.snapshot.seq, pointer.seq
            ))));
        }
        if signed.snapshot.record_type != rt {
            return Err(CoreError::Crypto(CryptoError::Kdf(format!(
                "snapshot record_type {:?} != expected {:?}",
                signed.snapshot.record_type, rt
            ))));
        }
        verify_snapshot(&self.keys.identity_pk, &signed).map_err(CoreError::Crypto)?;
        Ok(Some((signed, head_address)))
    }

    async fn write_snapshot(
        &self,
        rt: RecordType,
        seq: u64,
        prev_address: Option<ChunkAddress>,
        frames: Vec<RecordFrame>,
    ) -> Result<(), CoreError> {
        let snapshot = Snapshot {
            format_version: FormatVersion::V1,
            record_type: rt,
            seq,
            prev_address,
            frames,
            backup_targets: vec![BackupTarget::Vault],
        };
        let signed = sign_snapshot(&self.keys.identity_sk, snapshot)?;
        let signed_bytes = cbor_to_vec(&signed)
            .map_err(|e| CoreError::Crypto(CryptoError::Kdf(format!("CBOR: {e}"))))?;
        let snap_key = derive_record_aead_key(&self.keys.user_aead_master, self.keys.user_id, rt)?;
        let snap_aad = snapshot_aad(self.keys.user_id, rt, seq);
        let snap_ct = aead_seal(&snap_key, &signed_bytes, &snap_aad)?;
        let (snap_chunks, snap_dm) = se_encrypt(&snap_ct).map_err(CoreError::Crypto)?;
        self.chunks.put_chunks(&snap_chunks).await?;

        let head_key =
            derive_head_pointer_aead_key(&self.keys.user_aead_master, self.keys.user_id)?;
        let stored = seal_head_pointer(
            &head_key,
            &self.keys.identity_sk,
            &self.keys.cluster_id,
            &self.keys.user_id,
            rt,
            snap_dm,
            seq,
        )?;
        self.heads.put(rt, stored).await?;
        Ok(())
    }
}

/// Borrow the user's identity material out of a `RecordStore`. Used
/// by tests + tooling.
pub fn user_keys_of<C: ChunkTransport, H: HeadPointerTransport>(
    store: &RecordStore<C, H>,
) -> &UserKeys {
    &store.keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_dsa_65_keypair;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── Test transports ───────────────────────────────────────────

    struct InMemChunkTransport {
        inner: std::sync::Arc<Mutex<HashMap<[u8; 32], Vec<u8>>>>,
    }
    impl InMemChunkTransport {
        fn new() -> Self {
            Self {
                inner: std::sync::Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }
    #[async_trait]
    impl ChunkTransport for InMemChunkTransport {
        async fn put_chunks(&self, chunks: &[Chunk]) -> Result<(), CoreError> {
            let mut g = self.inner.lock().unwrap();
            for c in chunks {
                g.insert(c.address.0, c.bytes.clone());
            }
            Ok(())
        }
        async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError> {
            let g = self.inner.lock().unwrap();
            g.get(&address.0)
                .cloned()
                .ok_or(CoreError::Storage(crate::errors::StorageError::NotFound))
        }
    }

    struct InMemHeadTransport {
        inner: std::sync::Arc<Mutex<HashMap<u8, StoredHeadPointer>>>,
    }
    impl InMemHeadTransport {
        fn new() -> Self {
            Self {
                inner: std::sync::Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }
    #[async_trait]
    impl HeadPointerTransport for InMemHeadTransport {
        async fn get(&self, rt: RecordType) -> Result<Option<StoredHeadPointer>, CoreError> {
            let g = self.inner.lock().unwrap();
            Ok(g.get(&rt.as_u8()).cloned())
        }
        async fn put(&self, rt: RecordType, stored: StoredHeadPointer) -> Result<(), CoreError> {
            let mut g = self.inner.lock().unwrap();
            // Soft monotonicity check (matches what the hub will do).
            if let Some(existing) = g.get(&rt.as_u8()) {
                if stored.seq <= existing.seq {
                    return Err(CoreError::Crypto(CryptoError::Kdf(format!(
                        "non-monotonic seq: {} <= {}",
                        stored.seq, existing.seq
                    ))));
                }
            }
            g.insert(rt.as_u8(), stored);
            Ok(())
        }
    }

    fn build_store() -> RecordStore<InMemChunkTransport, InMemHeadTransport> {
        let kp = ml_dsa_65_keypair().unwrap();
        let phrase = crate::crypto::seedphrase::SeedPhrase::generate().unwrap();
        let seed = phrase.to_seed("");
        let master = crate::record::user_keys::derive_user_aead_master(&seed);
        let keys = UserKeys {
            user_id: UserId([42u8; 16]),
            cluster_id: ClusterId([7u8; 32]),
            identity_pk: kp.public,
            identity_sk: kp.secret,
            user_aead_master: master,
        };
        RecordStore::new(keys, InMemChunkTransport::new(), InMemHeadTransport::new())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn put_get_round_trip_single_record() {
        let store = build_store();
        let payload = b"my credential: pw=hunter2";
        let id = store.put(RecordType::Credential, payload).await.unwrap();
        let got = store
            .get(RecordType::Credential, id)
            .await
            .unwrap()
            .expect("record present");
        assert_eq!(got, payload);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_returns_all_live_records() {
        let store = build_store();
        let id_a = store.put(RecordType::Credential, b"first").await.unwrap();
        let id_b = store.put(RecordType::Credential, b"second").await.unwrap();
        let listed = store.list(RecordType::Credential).await.unwrap();
        assert_eq!(listed.len(), 2);
        let map: HashMap<_, _> = listed.into_iter().collect();
        assert_eq!(map.get(&id_a).unwrap().as_slice(), b"first");
        assert_eq!(map.get(&id_b).unwrap().as_slice(), b"second");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_removes_record_from_list() {
        let store = build_store();
        let id = store.put(RecordType::Credential, b"x").await.unwrap();
        let _ = store.put(RecordType::Credential, b"y").await.unwrap();
        store.delete(RecordType::Credential, id).await.unwrap();
        let listed = store.list(RecordType::Credential).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_ne!(listed[0].0, id);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn put_or_replace_updates_existing_record() {
        let store = build_store();
        let id = store.put(RecordType::Credential, b"v1").await.unwrap();
        store
            .put_or_replace(RecordType::Credential, id, b"v2-updated")
            .await
            .unwrap();
        let got = store
            .get(RecordType::Credential, id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got, b"v2-updated");
        // Still only one record live.
        assert_eq!(store.list(RecordType::Credential).await.unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn record_types_isolated() {
        let store = build_store();
        store.put(RecordType::Credential, b"cred").await.unwrap();
        store.put(RecordType::Alias, b"alias").await.unwrap();
        assert_eq!(store.list(RecordType::Credential).await.unwrap().len(), 1);
        assert_eq!(store.list(RecordType::Alias).await.unwrap().len(), 1);
        assert_eq!(store.list(RecordType::AliasMessage).await.unwrap().len(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_seq_monotonic() {
        let store = build_store();
        for i in 0..5 {
            let payload = format!("record-{i}").into_bytes();
            store.put(RecordType::Credential, &payload).await.unwrap();
        }
        // We can't directly read seq from outside, but list size
        // proves a 5th-gen snapshot was constructed by walking the
        // chain. Cross-check by also fetching head and seq.
        let head = store
            .heads
            .get(RecordType::Credential)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.seq, 4); // 0..4 inclusive
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_missing_record_returns_none() {
        let store = build_store();
        let res = store
            .get(RecordType::Credential, RecordId([0xff; 16]))
            .await
            .unwrap();
        assert!(res.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_list_when_no_writes() {
        let store = build_store();
        assert!(store.list(RecordType::Credential).await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_payload_round_trip() {
        let store = build_store();
        let payload: Vec<u8> = (0..(50 * 1024)).map(|i| (i & 0xff) as u8).collect();
        let id = store.put(RecordType::Credential, &payload).await.unwrap();
        let got = store
            .get(RecordType::Credential, id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got, payload);
    }
}
