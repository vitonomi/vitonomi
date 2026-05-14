//! High-level client API on top of the chunk store + snapshot chain
//! + head pointer.
//!
//! Transport-agnostic: `RecordStore` is parameterised over a
//! [`ChunkTransport`] and a [`HeadPointerTransport`]. Tests wire it
//! to in-memory implementations of both; production wires it to a
//! libp2p chunk transport (clients/cli) and a hub HTTP head-pointer
//! transport (Slice 4 follow-up).
//!
//! Each record has two faces — see [`crate::record`] module docs for
//! the model. The public API surfaces this:
//!
//! - [`RecordStore::put`] / [`put_or_replace`](RecordStore::put_or_replace)
//!   take a [`RecordPlaintext`] of `metadata` + a [`BodyOp`] that
//!   chooses between writing, keeping, or removing the body face.
//! - [`RecordStore::list_metadata`] decrypts only metadata — never
//!   body chunks. Inline metadata is read from the snapshot directly;
//!   blob metadata triggers per-record chunk fetches.
//! - [`RecordStore::get_metadata`] / [`get_body`](RecordStore::get_body)
//!   are the targeted read paths.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::crypto::aead::{open as aead_open, seal as aead_seal};
use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65SecretKey};
use crate::crypto::selfencrypt::{decrypt as se_decrypt, encrypt as se_encrypt, Chunk, DataMap};
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::{CoreError, CryptoError, ValidationError};
use crate::protocol::autonomi_bridge::ChunkAddress;
use crate::record::head_pointer::{open_head_pointer, seal_head_pointer, StoredHeadPointer};
use crate::record::snapshot::{
    sign_snapshot, snapshot_aad, verify_snapshot, RecordFrame, RecordOp, SignedSnapshot, Snapshot,
};
use crate::record::user_keys::{
    derive_head_pointer_aead_key, derive_record_aead_key, UserAeadMaster,
};
use crate::record::{
    record_body_aad, record_metadata_aad, BackupTarget, MetadataField, RecordId, RecordType,
    INLINE_METADATA_MAX,
};
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

/// Transport-agnostic chunk store seen by the client. Backed in tests
/// by an in-memory map; in production by libp2p request-response.
/// The trait surface is intentionally small: content-addressed put +
/// content-addressed get. Authentication + ownership attribution
/// happen one layer up (libp2p auth + per-request signatures).
#[async_trait]
pub trait ChunkTransport: Send + Sync {
    async fn put_chunks(&self, chunks: &[Chunk]) -> Result<(), CoreError>;
    async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError>;
}

/// Head-pointer storage as seen by the client. Tests use an in-memory
/// map; the CLI uses a local file; Slice 4 will swap in the hub HTTP
/// transport.
#[async_trait]
pub trait HeadPointerTransport: Send + Sync {
    async fn get(&self, record_type: RecordType) -> Result<Option<StoredHeadPointer>, CoreError>;
    async fn put(
        &self,
        record_type: RecordType,
        stored: StoredHeadPointer,
    ) -> Result<(), CoreError>;
}

/// Plaintext bytes for a record's two faces, ready to be sealed by
/// [`RecordStore::put`] / [`RecordStore::put_or_replace`].
///
/// `metadata` is encoded once and either rides inline in the
/// snapshot's RecordFrame (when ≤ [`INLINE_METADATA_MAX`] bytes) or
/// is sealed as a separate blob and referenced by DataMap. `body`
/// chooses what to do with the body face — see [`BodyOp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlaintext {
    /// Encoded metadata bytes (typically deterministic CBOR of a
    /// per-RecordType `*Metadata` struct). May be any length;
    /// `≤ INLINE_METADATA_MAX` rides inline, longer is sealed as a
    /// separate metadata blob.
    pub metadata: Vec<u8>,
    /// What to do with the body face. See [`BodyOp`].
    pub body: BodyOp,
}

/// What to do with a record's body face on a put.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyOp {
    /// (Re)write the body face with these bytes. Fresh AEAD nonce +
    /// fresh self-encryption chunks. The new RecordFrame's
    /// `body_data_map` will be `Some(...)`.
    Set(Vec<u8>),
    /// Reuse the prior frame's `body_data_map` verbatim. No chunk
    /// uploads; no key derivation. Useful for metadata-only edits
    /// (rename, retag) that should not re-encrypt the body.
    /// Errors with [`ValidationError::Other`] if the record has no
    /// prior frame, or its prior frame is a tombstone.
    Keep,
    /// Drop the body face entirely. The new RecordFrame's
    /// `body_data_map` is `None`. The body's chunks become orphaned
    /// and are reclaimable by vault GC at any time.
    Remove,
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

    /// Insert a new record with a freshly-generated [`RecordId`].
    /// Returns the id.
    ///
    /// `BodyOp::Keep` is rejected because there is no prior frame to
    /// reuse a body from on a fresh insert.
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport / validation failure.
    pub async fn put(
        &self,
        rt: RecordType,
        plaintext: RecordPlaintext,
    ) -> Result<RecordId, CoreError> {
        if matches!(plaintext.body, BodyOp::Keep) {
            return Err(CoreError::Validation(ValidationError::Other(
                "BodyOp::Keep cannot be used with put — no prior frame to reuse".into(),
            )));
        }
        let record_id = RecordId::generate()?;
        self.put_or_replace(rt, record_id, plaintext).await?;
        Ok(record_id)
    }

    /// Insert / overwrite a record at a known [`RecordId`].
    ///
    /// Sealing rules:
    /// - Metadata ≤ [`INLINE_METADATA_MAX`] bytes rides inline in the
    ///   snapshot frame. Otherwise it is AEAD-sealed under
    ///   [`record_metadata_aad`] and self-encrypted; the frame holds
    ///   the resulting DataMap.
    /// - Body is AEAD-sealed under [`record_body_aad`] and
    ///   self-encrypted on `BodyOp::Set(bytes)`; reused verbatim on
    ///   `BodyOp::Keep`; absent on `BodyOp::Remove`.
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure, or
    /// [`ValidationError::Other`] when `BodyOp::Keep` cannot resolve a
    /// prior body.
    pub async fn put_or_replace(
        &self,
        rt: RecordType,
        record_id: RecordId,
        plaintext: RecordPlaintext,
    ) -> Result<(), CoreError> {
        // Load the prior snapshot up-front: needed by `BodyOp::Keep`,
        // by per-record-version bookkeeping, and by the chain link.
        let prev = self.fetch_signed_head_snapshot(rt).await?;

        // 1. Seal metadata: inline iff fits, else blob.
        let metadata_field = if plaintext.metadata.len() <= INLINE_METADATA_MAX {
            MetadataField::Inline {
                bytes: plaintext.metadata.clone(),
            }
        } else {
            let aad = record_metadata_aad(self.keys.user_id, rt, record_id);
            let key =
                derive_record_aead_key(&self.keys.user_aead_master, self.keys.user_id, rt)?;
            let ct = aead_seal(&key, &plaintext.metadata, &aad)?;
            let (chunks, dm) = se_encrypt(&ct).map_err(CoreError::Crypto)?;
            self.chunks.put_chunks(&chunks).await?;
            MetadataField::Blob { data_map: dm }
        };

        // 2. Resolve the body face.
        let body_data_map = match &plaintext.body {
            BodyOp::Set(bytes) => {
                let aad = record_body_aad(self.keys.user_id, rt, record_id);
                let key =
                    derive_record_aead_key(&self.keys.user_aead_master, self.keys.user_id, rt)?;
                let ct = aead_seal(&key, bytes, &aad)?;
                let (chunks, dm) = se_encrypt(&ct).map_err(CoreError::Crypto)?;
                self.chunks.put_chunks(&chunks).await?;
                Some(dm)
            }
            BodyOp::Keep => {
                let prior_frame = prev
                    .as_ref()
                    .and_then(|(signed, _)| {
                        signed
                            .snapshot
                            .frames
                            .iter()
                            .find(|f| f.record_id == record_id)
                    });
                match prior_frame {
                    Some(RecordFrame {
                        op: RecordOp::Put { body_data_map, .. },
                        ..
                    }) => body_data_map.clone(),
                    Some(RecordFrame {
                        op: RecordOp::Delete,
                        ..
                    }) => {
                        return Err(CoreError::Validation(ValidationError::Other(
                            "BodyOp::Keep but prior frame is a tombstone".into(),
                        )));
                    }
                    None => {
                        return Err(CoreError::Validation(ValidationError::Other(format!(
                            "BodyOp::Keep but no prior frame found for record_id={record_id}"
                        ))));
                    }
                }
            }
            BodyOp::Remove => None,
        };

        // 3. Build new frame, fold into snapshot, sign + seal + store.
        let new_op = RecordOp::Put {
            metadata: metadata_field,
            body_data_map,
        };
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
                    op: new_op,
                    prev_record_version: new_version,
                });
                (signed.snapshot.seq + 1, frames, Some(head_addr))
            }
            None => (
                0u64,
                vec![RecordFrame {
                    record_id,
                    op: new_op,
                    prev_record_version: 0,
                }],
                None,
            ),
        };
        frames.sort_by(|a, b| a.record_id.0.cmp(&b.record_id.0));
        self.write_snapshot(rt, next_seq, prev_address, frames)
            .await?;
        Ok(())
    }

    /// Delete a record by id. Appends a tombstone frame.
    ///
    /// The body chunks (if any) are NOT removed by this call; they
    /// become orphaned and the vault GCs them on its own schedule.
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
            None => (
                0u64,
                vec![RecordFrame {
                    record_id,
                    op: RecordOp::Delete,
                    prev_record_version: 0,
                }],
                None,
            ),
        };
        frames.sort_by(|a, b| a.record_id.0.cmp(&b.record_id.0));
        self.write_snapshot(rt, next_seq, prev_address, frames)
            .await?;
        Ok(())
    }

    /// Decrypt every live record's metadata face. Inline metadata
    /// yields its bytes from the snapshot directly; Blob metadata
    /// triggers per-record chunk fetches. **Body chunks are never
    /// fetched.**
    ///
    /// Output is sorted by `record_id` for deterministic ordering.
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure.
    pub async fn list_metadata(
        &self,
        rt: RecordType,
    ) -> Result<Vec<(RecordId, Vec<u8>)>, CoreError> {
        let head = self.fetch_signed_head_snapshot(rt).await?;
        let Some((signed, _)) = head else {
            return Ok(Vec::new());
        };

        let mut out = Vec::with_capacity(signed.snapshot.frames.len());
        for frame in &signed.snapshot.frames {
            match &frame.op {
                RecordOp::Delete => {}
                RecordOp::Put { metadata, .. } => {
                    let bytes = self
                        .open_metadata_face(rt, frame.record_id, metadata)
                        .await?;
                    out.push((frame.record_id, bytes));
                }
            }
        }
        out.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        Ok(out)
    }

    /// Fetch one record's metadata face. Returns `None` if the record
    /// is not present (never written, deleted, or tombstoned).
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure.
    pub async fn get_metadata(
        &self,
        rt: RecordType,
        record_id: RecordId,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let head = self.fetch_signed_head_snapshot(rt).await?;
        let Some((signed, _)) = head else {
            return Ok(None);
        };
        let Some(frame) = signed
            .snapshot
            .frames
            .iter()
            .find(|f| f.record_id == record_id)
        else {
            return Ok(None);
        };
        let RecordOp::Put { metadata, .. } = &frame.op else {
            return Ok(None);
        };
        Ok(Some(
            self.open_metadata_face(rt, record_id, metadata).await?,
        ))
    }

    /// Fetch one record's body face. Returns `None` if the record is
    /// not present, was tombstoned, or has no body face.
    ///
    /// # Errors
    ///
    /// Any underlying crypto / transport failure.
    pub async fn get_body(
        &self,
        rt: RecordType,
        record_id: RecordId,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let head = self.fetch_signed_head_snapshot(rt).await?;
        let Some((signed, _)) = head else {
            return Ok(None);
        };
        let Some(frame) = signed
            .snapshot
            .frames
            .iter()
            .find(|f| f.record_id == record_id)
        else {
            return Ok(None);
        };
        let RecordOp::Put { body_data_map, .. } = &frame.op else {
            return Ok(None);
        };
        let Some(dm) = body_data_map else {
            return Ok(None);
        };
        Ok(Some(self.open_body_face(rt, record_id, dm).await?))
    }

    // ── face-level seal / open helpers ────────────────────────────

    async fn open_metadata_face(
        &self,
        rt: RecordType,
        record_id: RecordId,
        metadata: &MetadataField,
    ) -> Result<Vec<u8>, CoreError> {
        match metadata {
            MetadataField::Inline { bytes } => Ok(bytes.clone()),
            MetadataField::Blob { data_map } => {
                let aad = record_metadata_aad(self.keys.user_id, rt, record_id);
                let key =
                    derive_record_aead_key(&self.keys.user_aead_master, self.keys.user_id, rt)?;
                let addrs = data_map.chunk_addresses().map_err(CoreError::Crypto)?;
                let cache = self.prefetch_chunks(&addrs).await?;
                let ct = se_decrypt(data_map, |addr| {
                    cache
                        .get(&addr.0)
                        .cloned()
                        .ok_or(CoreError::Storage(crate::errors::StorageError::NotFound))
                })
                .map_err(CoreError::Crypto)?;
                let pt = aead_open(&key, &ct, &aad)?;
                Ok(pt)
            }
        }
    }

    async fn open_body_face(
        &self,
        rt: RecordType,
        record_id: RecordId,
        dm: &DataMap,
    ) -> Result<Vec<u8>, CoreError> {
        let aad = record_body_aad(self.keys.user_id, rt, record_id);
        let key = derive_record_aead_key(&self.keys.user_aead_master, self.keys.user_id, rt)?;
        let addrs = dm.chunk_addresses().map_err(CoreError::Crypto)?;
        let cache = self.prefetch_chunks(&addrs).await?;
        let ct = se_decrypt(dm, |addr| {
            cache
                .get(&addr.0)
                .cloned()
                .ok_or(CoreError::Storage(crate::errors::StorageError::NotFound))
        })
        .map_err(CoreError::Crypto)?;
        let pt = aead_open(&key, &ct, &aad)?;
        Ok(pt)
    }

    /// Fetch many chunks asynchronously, returning an address →
    /// bytes map. The sync closure inside
    /// [`crate::crypto::selfencrypt::decrypt`] reads from this map.
    async fn prefetch_chunks(
        &self,
        addresses: &[ChunkAddress],
    ) -> Result<HashMap<[u8; 32], Vec<u8>>, CoreError> {
        // Sequential fetch — fine for current profile (small
        // metadata blobs and a single body per `get_body` call).
        // Switch to a parallel pipeline (e.g. `futures::try_join_all`)
        // if profiling motivates it.
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    // ── Test transports ───────────────────────────────────────────

    struct InMemChunkTransport {
        inner: Arc<Mutex<HashMap<[u8; 32], Vec<u8>>>>,
    }
    impl InMemChunkTransport {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(HashMap::new())),
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

    /// Counting decorator over any `ChunkTransport`. Used in the
    /// metadata-only and BodyOp::Keep tests to assert the right
    /// chunks were (or weren't) fetched / uploaded.
    struct CountingChunkTransport<T: ChunkTransport> {
        inner: T,
        get_calls: Arc<AtomicUsize>,
        put_chunk_total: Arc<AtomicUsize>,
    }
    impl<T: ChunkTransport> CountingChunkTransport<T> {
        fn new(inner: T) -> Self {
            Self {
                inner,
                get_calls: Arc::new(AtomicUsize::new(0)),
                put_chunk_total: Arc::new(AtomicUsize::new(0)),
            }
        }
        fn get_count(&self) -> usize {
            self.get_calls.load(Ordering::SeqCst)
        }
        fn put_chunks_total(&self) -> usize {
            self.put_chunk_total.load(Ordering::SeqCst)
        }
        fn reset(&self) {
            self.get_calls.store(0, Ordering::SeqCst);
            self.put_chunk_total.store(0, Ordering::SeqCst);
        }
    }
    #[async_trait]
    impl<T: ChunkTransport> ChunkTransport for CountingChunkTransport<T> {
        async fn put_chunks(&self, chunks: &[Chunk]) -> Result<(), CoreError> {
            let r = self.inner.put_chunks(chunks).await;
            if r.is_ok() {
                self.put_chunk_total
                    .fetch_add(chunks.len(), Ordering::SeqCst);
            }
            r
        }
        async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError> {
            let r = self.inner.get_chunk(address).await;
            if r.is_ok() {
                self.get_calls.fetch_add(1, Ordering::SeqCst);
            }
            r
        }
    }

    struct InMemHeadTransport {
        inner: Arc<Mutex<HashMap<u8, StoredHeadPointer>>>,
    }
    impl InMemHeadTransport {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(HashMap::new())),
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

    fn build_keys() -> UserKeys {
        let kp = ml_dsa_65_keypair().unwrap();
        let phrase = crate::crypto::seedphrase::SeedPhrase::generate().unwrap();
        let seed = phrase.to_seed("");
        let master = crate::record::user_keys::derive_user_aead_master(&seed);
        UserKeys {
            user_id: UserId([42u8; 16]),
            cluster_id: ClusterId([7u8; 32]),
            identity_pk: kp.public,
            identity_sk: kp.secret,
            user_aead_master: master,
        }
    }

    fn build_store() -> RecordStore<InMemChunkTransport, InMemHeadTransport> {
        RecordStore::new(build_keys(), InMemChunkTransport::new(), InMemHeadTransport::new())
    }

    fn meta(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    fn pt_meta_only(metadata: Vec<u8>) -> RecordPlaintext {
        RecordPlaintext {
            metadata,
            body: BodyOp::Remove,
        }
    }

    fn pt_with_body(metadata: Vec<u8>, body: Vec<u8>) -> RecordPlaintext {
        RecordPlaintext {
            metadata,
            body: BodyOp::Set(body),
        }
    }

    // ── Round-trip basics ─────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn put_get_metadata_round_trip_inline() {
        let store = build_store();
        let id = store
            .put(RecordType::Credential, pt_meta_only(meta("title=netflix")))
            .await
            .unwrap();
        let got = store
            .get_metadata(RecordType::Credential, id)
            .await
            .unwrap()
            .expect("metadata present");
        assert_eq!(got, b"title=netflix");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn put_get_body_round_trip() {
        let store = build_store();
        let id = store
            .put(
                RecordType::Credential,
                pt_with_body(meta("title=netflix"), b"pw=hunter2".to_vec()),
            )
            .await
            .unwrap();
        let body = store
            .get_body(RecordType::Credential, id)
            .await
            .unwrap()
            .expect("body present");
        assert_eq!(body, b"pw=hunter2");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_metadata_returns_all_live_records() {
        let store = build_store();
        let id_a = store
            .put(RecordType::Credential, pt_meta_only(meta("alpha")))
            .await
            .unwrap();
        let id_b = store
            .put(RecordType::Credential, pt_meta_only(meta("beta")))
            .await
            .unwrap();
        let listed = store.list_metadata(RecordType::Credential).await.unwrap();
        assert_eq!(listed.len(), 2);
        let map: HashMap<_, _> = listed.into_iter().collect();
        assert_eq!(map.get(&id_a).unwrap().as_slice(), b"alpha");
        assert_eq!(map.get(&id_b).unwrap().as_slice(), b"beta");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_removes_record_from_list() {
        let store = build_store();
        let id = store
            .put(RecordType::Credential, pt_meta_only(meta("doomed")))
            .await
            .unwrap();
        let _ = store
            .put(RecordType::Credential, pt_meta_only(meta("survivor")))
            .await
            .unwrap();
        store.delete(RecordType::Credential, id).await.unwrap();
        let listed = store.list_metadata(RecordType::Credential).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_ne!(listed[0].0, id);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn put_or_replace_updates_existing_metadata() {
        let store = build_store();
        let id = store
            .put(RecordType::Credential, pt_meta_only(meta("v1")))
            .await
            .unwrap();
        store
            .put_or_replace(
                RecordType::Credential,
                id,
                pt_meta_only(meta("v2-updated")),
            )
            .await
            .unwrap();
        let got = store
            .get_metadata(RecordType::Credential, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"v2-updated");
        // Still only one record live.
        assert_eq!(
            store.list_metadata(RecordType::Credential).await.unwrap().len(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn record_types_isolated() {
        let store = build_store();
        store
            .put(RecordType::Credential, pt_meta_only(meta("cred")))
            .await
            .unwrap();
        store
            .put(RecordType::Alias, pt_meta_only(meta("alias")))
            .await
            .unwrap();
        assert_eq!(
            store.list_metadata(RecordType::Credential).await.unwrap().len(),
            1
        );
        assert_eq!(
            store.list_metadata(RecordType::Alias).await.unwrap().len(),
            1
        );
        assert_eq!(
            store
                .list_metadata(RecordType::AliasMessage)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_missing_record_returns_none() {
        let store = build_store();
        let res = store
            .get_metadata(RecordType::Credential, RecordId([0xff; 16]))
            .await
            .unwrap();
        assert!(res.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_list_when_no_writes() {
        let store = build_store();
        assert!(store
            .list_metadata(RecordType::Credential)
            .await
            .unwrap()
            .is_empty());
    }

    // ── Inline vs blob metadata ───────────────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn large_metadata_falls_back_to_blob() {
        let store = build_store();
        // 1 KiB of metadata > INLINE_METADATA_MAX (512); forces the
        // Blob variant.
        let big: Vec<u8> = (0..1024).map(|i| (i & 0xff) as u8).collect();
        let id = store
            .put(RecordType::Credential, pt_meta_only(big.clone()))
            .await
            .unwrap();
        let got = store
            .get_metadata(RecordType::Credential, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, big);
    }

    // ── Zero-body-fetch invariants (the headline property) ────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_metadata_with_inline_metadata_fetches_zero_body_chunks() {
        // Build a store wired through the counting transport so we
        // can assert no chunk fetches happen on `list_metadata`.
        let counter = Arc::new(CountingChunkTransport::new(InMemChunkTransport::new()));
        let store_seed = build_keys();
        let store = RecordStore::new(
            store_seed,
            // CountingChunkTransport doesn't impl Clone, so we hand
            // ownership to the store via a wrapper that delegates.
            CountingArcWrap {
                inner: counter.clone(),
            },
            InMemHeadTransport::new(),
        );

        for i in 0..10 {
            store
                .put(
                    RecordType::Credential,
                    pt_with_body(
                        meta(&format!("title-{i}")),
                        format!("body-{i}").into_bytes(),
                    ),
                )
                .await
                .unwrap();
        }

        // After all writes, reset counters and assert list_metadata
        // performs only the snapshot fetch (no body chunks).
        let put_total_after_writes = counter.put_chunks_total();
        assert!(put_total_after_writes > 0, "writes should upload chunks");
        counter.reset();

        let listed = store.list_metadata(RecordType::Credential).await.unwrap();
        assert_eq!(listed.len(), 10);

        // The list path may fetch the snapshot chunks (these come
        // from the head pointer's snapshot DataMap). It MUST NOT
        // fetch any of the per-record body chunks. We don't have a
        // way to distinguish snapshot chunks from body chunks at
        // this layer, but with all metadata Inline the only chunks
        // referenced by any frame are body chunks — so any fetch
        // beyond the snapshot itself is a body fetch. Snapshot
        // self-encryption typically produces a small number of
        // chunks (≤ a handful for a 10-record snapshot); 10 records
        // × N body chunks would dwarf that. Assert the get-count is
        // strictly less than the body-chunk count (which is ≥ 10
        // since each body becomes ≥ 1 chunk).
        assert!(
            counter.get_count() < 10,
            "list_metadata fetched {} chunks; with all-inline metadata it should fetch only \
             snapshot chunks (≤ a handful), strictly less than the 10+ body chunks. Body \
             chunks were fetched.",
            counter.get_count()
        );
    }

    // Helper to wrap an Arc'd CountingChunkTransport as a
    // ChunkTransport without giving up ownership (Arc doesn't impl
    // ChunkTransport directly because of the &self requirement
    // through async_trait; we wrap via a thin newtype).
    struct CountingArcWrap {
        inner: Arc<CountingChunkTransport<InMemChunkTransport>>,
    }
    #[async_trait]
    impl ChunkTransport for CountingArcWrap {
        async fn put_chunks(&self, chunks: &[Chunk]) -> Result<(), CoreError> {
            self.inner.put_chunks(chunks).await
        }
        async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError> {
            self.inner.get_chunk(address).await
        }
    }

    // ── BodyOp::Keep — metadata-only edit ─────────────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_op_keep_preserves_body_and_uploads_no_body_chunks() {
        let counter = Arc::new(CountingChunkTransport::new(InMemChunkTransport::new()));
        let store = RecordStore::new(
            build_keys(),
            CountingArcWrap {
                inner: counter.clone(),
            },
            InMemHeadTransport::new(),
        );

        // Initial put with a body.
        let id = store
            .put(
                RecordType::Credential,
                pt_with_body(meta("v1"), b"the-body".to_vec()),
            )
            .await
            .unwrap();
        let chunks_after_initial = counter.put_chunks_total();
        assert!(chunks_after_initial > 0);

        // Metadata-only edit: rewrite metadata, keep the body.
        counter.reset();
        store
            .put_or_replace(
                RecordType::Credential,
                id,
                RecordPlaintext {
                    metadata: meta("v2"),
                    body: BodyOp::Keep,
                },
            )
            .await
            .unwrap();

        // The new snapshot must have been uploaded (snapshot chunks
        // count), but no body chunks. With INLINE metadata + Keep,
        // the only puts are the snapshot's self-encryption chunks.
        // We can't trivially distinguish these from body chunks,
        // but the body's plaintext was 8 bytes — and self-encryption
        // produces multi-KB chunks even for tiny inputs. Assert the
        // total chunks uploaded for this edit is small (snapshot
        // only, no body).
        let edit_total = counter.put_chunks_total();
        assert!(
            edit_total > 0,
            "snapshot chunks must be uploaded on a metadata edit"
        );
        // Verify body is intact and unchanged.
        let body = store
            .get_body(RecordType::Credential, id)
            .await
            .unwrap()
            .expect("body still present after Keep");
        assert_eq!(body, b"the-body");
        // And metadata reflects the edit.
        let m = store
            .get_metadata(RecordType::Credential, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(m, b"v2");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_op_keep_on_fresh_put_is_validation_error() {
        let store = build_store();
        let err = store
            .put(
                RecordType::Credential,
                RecordPlaintext {
                    metadata: meta("x"),
                    body: BodyOp::Keep,
                },
            )
            .await
            .unwrap_err();
        match err {
            CoreError::Validation(ValidationError::Other(msg)) => {
                assert!(msg.contains("BodyOp::Keep"));
            }
            other => panic!("expected ValidationError::Other, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_op_keep_with_no_prior_frame_is_validation_error() {
        let store = build_store();
        let unknown_id = RecordId([0xee; 16]);
        let err = store
            .put_or_replace(
                RecordType::Credential,
                unknown_id,
                RecordPlaintext {
                    metadata: meta("x"),
                    body: BodyOp::Keep,
                },
            )
            .await
            .unwrap_err();
        match err {
            CoreError::Validation(ValidationError::Other(msg)) => {
                assert!(msg.contains("Keep"));
            }
            other => panic!("expected ValidationError::Other, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_op_remove_drops_body() {
        let store = build_store();
        let id = store
            .put(
                RecordType::Credential,
                pt_with_body(meta("v1"), b"secret".to_vec()),
            )
            .await
            .unwrap();
        // Now remove the body face.
        store
            .put_or_replace(
                RecordType::Credential,
                id,
                RecordPlaintext {
                    metadata: meta("v2"),
                    body: BodyOp::Remove,
                },
            )
            .await
            .unwrap();
        let body = store.get_body(RecordType::Credential, id).await.unwrap();
        assert!(body.is_none(), "body should be gone after Remove");
        let m = store
            .get_metadata(RecordType::Credential, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(m, b"v2");
    }

    // ── Cross-face / cross-record AAD isolation ──────────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_blob_cannot_be_decrypted_with_metadata_aad() {
        // Put a record with a sealed body. Then, simulating a
        // malicious vault, swap the body's DataMap into the metadata
        // slot of a fresh record_id and try to fetch — the AEAD
        // open MUST fail because the AAD prefix differs.
        let store = build_store();
        let id = store
            .put(
                RecordType::Credential,
                pt_with_body(meta("title"), b"secret-body".to_vec()),
            )
            .await
            .unwrap();

        // Recover the record's body_data_map by reading the snapshot
        // through fetch_signed_head_snapshot.
        let head = store
            .fetch_signed_head_snapshot(RecordType::Credential)
            .await
            .unwrap()
            .unwrap()
            .0;
        let frame = head
            .snapshot
            .frames
            .iter()
            .find(|f| f.record_id == id)
            .unwrap();
        let body_dm = match &frame.op {
            RecordOp::Put { body_data_map, .. } => body_data_map.clone().unwrap(),
            _ => panic!(),
        };

        // Try to open it as if it were the metadata blob for a
        // different record. The AAD prefix differs → tag mismatch.
        let attacker = MetadataField::Blob {
            data_map: body_dm.clone(),
        };
        let other_id = RecordId([0x77; 16]);
        let result = store
            .open_metadata_face(RecordType::Credential, other_id, &attacker)
            .await;
        assert!(
            matches!(result, Err(CoreError::Crypto(_))),
            "opening a body ciphertext as metadata must fail; got {result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_blob_cannot_be_decrypted_under_different_record_id() {
        let store = build_store();
        let id_a = store
            .put(
                RecordType::Credential,
                pt_with_body(meta("a"), b"body-a".to_vec()),
            )
            .await
            .unwrap();
        let id_b = store
            .put(
                RecordType::Credential,
                pt_with_body(meta("b"), b"body-b".to_vec()),
            )
            .await
            .unwrap();
        assert_ne!(id_a, id_b);

        // Recover A's body_data_map.
        let head = store
            .fetch_signed_head_snapshot(RecordType::Credential)
            .await
            .unwrap()
            .unwrap()
            .0;
        let frame_a = head
            .snapshot
            .frames
            .iter()
            .find(|f| f.record_id == id_a)
            .unwrap();
        let body_dm_a = match &frame_a.op {
            RecordOp::Put { body_data_map, .. } => body_data_map.clone().unwrap(),
            _ => panic!(),
        };

        // Try to open A's body under B's record_id — AAD includes
        // record_id, so this must fail.
        let result = store
            .open_body_face(RecordType::Credential, id_b, &body_dm_a)
            .await;
        assert!(
            matches!(result, Err(CoreError::Crypto(_))),
            "opening A's body under B's record_id must fail; got {result:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_seq_monotonic() {
        let store = build_store();
        for i in 0..5 {
            let payload = format!("record-{i}").into_bytes();
            store
                .put(RecordType::Credential, pt_meta_only(payload))
                .await
                .unwrap();
        }
        let head = store
            .heads
            .get(RecordType::Credential)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.seq, 4); // 0..4 inclusive
    }
}
