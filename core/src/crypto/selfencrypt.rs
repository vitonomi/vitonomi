//! Thin wrapper over upstream [`self_encryption`].
//!
//! vitonomi delegates chunk + DataMap byte layouts to the upstream
//! crate so a vitonomi vault is byte-identical to an Autonomi 2.0
//! object store. The upstream version is pinned in `core/Cargo.toml`
//! with `=0.35.0`; any version bump triggers a full conformance run.
//! Forking is forbidden — bugs are fixed upstream.
//!
//! The wrapper enforces two things over the raw API:
//!
//! 1. `Chunk` exposes the BLAKE3 content address alongside the bytes,
//!    so callers can verify `blake3(bytes) == address` and route the
//!    chunk to a content-addressed store.
//! 2. `DataMap` carries the upstream `DataMap` as opaque bytes
//!    (bincode-encoded). Downstream crates never construct or pattern-
//!    match the upstream type — that keeps the upstream out of the
//!    public API of every other workspace member.
//!
//! Input to `encrypt` MUST be AEAD ciphertext, never raw plaintext.
//! The AEAD-then-self-encryption order is what breaks self-
//! encryption's natural convergence and makes confirmation-of-file
//! attacks impossible across cluster members. See
//! `docs/encryption-flows.md`.

use bytes::Bytes;
use self_encryption::{
    decrypt as upstream_decrypt, encrypt as upstream_encrypt, DataMap as UpstreamDataMap,
};
use serde::{Deserialize, Serialize};

use crate::errors::{CryptoError, StorageError};
use crate::protocol::autonomi_bridge::ChunkAddress;

/// Encrypted chunk with its content address. Bytes are byte-identical
/// to what upstream `self_encryption::encrypt` emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub address: ChunkAddress,
    pub bytes: Vec<u8>,
}

/// Opaque DataMap envelope. Internally an upstream `DataMap`
/// bincode-encoded. The wrapper keeps the upstream type out of the
/// public API surface so downstream crates can't accidentally couple
/// to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DataMap(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl DataMap {
    /// Iterate the BLAKE3 content addresses (post-encryption hashes)
    /// referenced by this DataMap, in chunk-index order. The caller
    /// fetches each chunk by address before invoking [`decrypt`].
    ///
    /// # Errors
    ///
    /// `CryptoError::Kdf("data map decode: ...")` if the inner bytes
    /// are not a valid upstream DataMap.
    pub fn chunk_addresses(&self) -> Result<Vec<ChunkAddress>, CryptoError> {
        let dm = UpstreamDataMap::from_bytes(&self.0)
            .map_err(|e| CryptoError::Kdf(format!("data map decode: {e}")))?;
        let mut infos: Vec<_> = dm.chunk_identifiers.iter().collect();
        infos.sort_by_key(|info| info.index);
        Ok(infos
            .into_iter()
            .map(|info| ChunkAddress(info.dst_hash.0))
            .collect())
    }

    /// Original plaintext length recorded in the DataMap. Useful for
    /// sanity-checking + sizing the decrypt-output buffer.
    ///
    /// # Errors
    ///
    /// Same as [`chunk_addresses`].
    pub fn original_size(&self) -> Result<usize, CryptoError> {
        let dm = UpstreamDataMap::from_bytes(&self.0)
            .map_err(|e| CryptoError::Kdf(format!("data map decode: {e}")))?;
        Ok(dm.original_file_size())
    }
}

/// Run input bytes through upstream self-encryption. Input MUST be
/// AEAD ciphertext; raw plaintext is a privacy bug because upstream
/// is convergent.
///
/// # Errors
///
/// `CryptoError::Kdf(...)` on upstream failure (size below
/// `MIN_ENCRYPTABLE_BYTES = 3`, or internal encrypt error).
pub fn encrypt(bytes_in: &[u8]) -> Result<(Vec<Chunk>, DataMap), CryptoError> {
    if bytes_in.len() < self_encryption::MIN_ENCRYPTABLE_BYTES {
        return Err(CryptoError::Kdf(format!(
            "input too small for self-encryption: {} bytes (need ≥ {})",
            bytes_in.len(),
            self_encryption::MIN_ENCRYPTABLE_BYTES
        )));
    }

    let (upstream_dm, encrypted_chunks) = upstream_encrypt(Bytes::copy_from_slice(bytes_in))
        .map_err(|e| CryptoError::Kdf(format!("self_encryption::encrypt: {e}")))?;

    // Map upstream `Vec<EncryptedChunk>` (parallel to `dm.chunk_identifiers`
    // by chunk_index) into our `Vec<Chunk>`. We DO NOT recompute the
    // BLAKE3 of `content` here — the address comes from the DataMap's
    // `dst_hash`, which upstream guarantees is `blake3(content)`. A
    // separate conformance test asserts that invariant.
    let mut infos: Vec<_> = upstream_dm.chunk_identifiers.iter().collect();
    infos.sort_by_key(|info| info.index);

    if infos.len() != encrypted_chunks.len() {
        return Err(CryptoError::Kdf(format!(
            "self_encryption returned inconsistent shape: {} infos vs {} chunks",
            infos.len(),
            encrypted_chunks.len()
        )));
    }

    let chunks: Vec<Chunk> = infos
        .into_iter()
        .zip(encrypted_chunks.iter())
        .map(|(info, chunk)| Chunk {
            address: ChunkAddress(info.dst_hash.0),
            bytes: chunk.content.to_vec(),
        })
        .collect();

    let dm_bytes = upstream_dm
        .to_bytes()
        .map_err(|e| CryptoError::Kdf(format!("data map encode: {e}")))?;

    Ok((chunks, DataMap(dm_bytes)))
}

/// Verify that a chunk's BLAKE3 content hash matches the given
/// address. This is the address-integrity check the vault runs at
/// the storage boundary before persisting a chunk on disk.
///
/// Returns `Ok(())` on match, `Err(StorageError::AddressMismatch)`
/// otherwise.
///
/// # Errors
///
/// `StorageError::AddressMismatch` if `blake3(bytes) != address`.
pub fn verify_chunk_address(address: &ChunkAddress, bytes: &[u8]) -> Result<(), StorageError> {
    let actual = blake3::hash(bytes);
    if *actual.as_bytes() == address.0 {
        Ok(())
    } else {
        Err(StorageError::AddressMismatch {
            expected: address.0,
            actual: *actual.as_bytes(),
        })
    }
}

/// Reassemble bytes from a DataMap. Fetches chunks lazily via the
/// caller-supplied `fetcher` (typically backed by a `VaultStorage`
/// or an in-memory cache).
///
/// # Errors
///
/// - `CryptoError::Kdf(...)` if the DataMap fails to decode.
/// - Any error returned by `fetcher` propagates as
///   `CryptoError::Kdf(...)`.
/// - `CryptoError::Kdf(...)` on upstream decrypt failure.
pub fn decrypt<F>(data_map: &DataMap, mut fetcher: F) -> Result<Vec<u8>, CryptoError>
where
    F: FnMut(&ChunkAddress) -> Result<Vec<u8>, crate::errors::CoreError>,
{
    let upstream_dm = UpstreamDataMap::from_bytes(&data_map.0)
        .map_err(|e| CryptoError::Kdf(format!("data map decode: {e}")))?;

    // Sort by chunk_index so the EncryptedChunk slice we hand to
    // upstream is in canonical (index-sorted) order.
    let mut infos: Vec<_> = upstream_dm.chunk_identifiers.iter().collect();
    infos.sort_by_key(|info| info.index);

    // Fetch every chunk by its dst_hash (= BLAKE3 content address).
    let mut chunks: Vec<self_encryption::EncryptedChunk> = Vec::with_capacity(infos.len());
    for info in &infos {
        let addr = ChunkAddress(info.dst_hash.0);
        let bytes = fetcher(&addr).map_err(|e| {
            CryptoError::Kdf(format!(
                "chunk fetch failed for {}: {e}",
                hex_short(&addr.0)
            ))
        })?;
        chunks.push(self_encryption::EncryptedChunk {
            content: Bytes::from(bytes),
        });
    }

    let out = upstream_decrypt(&upstream_dm, &chunks)
        .map_err(|e| CryptoError::Kdf(format!("self_encryption decrypt: {e}")))?;

    Ok(out.to_vec())
}

fn hex_short(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    for b in &bytes[..8] {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_input(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i & 0xff) as u8).collect()
    }

    #[test]
    fn encrypt_rejects_tiny_input() {
        // 1 byte < MIN_ENCRYPTABLE_BYTES (3).
        let err = encrypt(&[0u8]).unwrap_err();
        assert!(matches!(err, CryptoError::Kdf(_)));
    }

    #[test]
    fn encrypt_decrypt_round_trip_3kib() {
        let bytes = fixed_input(3 * 1024);
        let (chunks, dm) = encrypt(&bytes).unwrap();
        assert!(chunks.len() >= 3, "must produce >= 3 chunks");

        // Fetcher backed by an in-memory map address → bytes.
        let map: std::collections::HashMap<[u8; 32], Vec<u8>> = chunks
            .iter()
            .map(|c| (c.address.0, c.bytes.clone()))
            .collect();
        let fetcher = |addr: &ChunkAddress| -> Result<Vec<u8>, crate::errors::CoreError> {
            map.get(&addr.0)
                .cloned()
                .ok_or_else(|| crate::errors::CoreError::Crypto(CryptoError::Kdf("missing".into())))
        };
        let out = decrypt(&dm, fetcher).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn encrypt_decrypt_round_trip_100kib() {
        let bytes = fixed_input(100 * 1024);
        let (chunks, dm) = encrypt(&bytes).unwrap();
        let map: std::collections::HashMap<[u8; 32], Vec<u8>> = chunks
            .iter()
            .map(|c| (c.address.0, c.bytes.clone()))
            .collect();
        let out = decrypt(&dm, |addr| {
            Ok(map
                .get(&addr.0)
                .cloned()
                .ok_or_else(|| crate::errors::CoreError::Crypto(CryptoError::Kdf("miss".into())))?)
        })
        .unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn chunk_address_equals_blake3_of_bytes() {
        let bytes = fixed_input(8 * 1024);
        let (chunks, _) = encrypt(&bytes).unwrap();
        for chunk in &chunks {
            let actual = blake3::hash(&chunk.bytes);
            assert_eq!(
                *actual.as_bytes(),
                chunk.address.0,
                "chunk address must equal blake3(bytes) — Autonomi invariant"
            );
        }
    }

    #[test]
    fn verify_chunk_address_accepts_match() {
        let bytes = fixed_input(8 * 1024);
        let (chunks, _) = encrypt(&bytes).unwrap();
        for chunk in &chunks {
            verify_chunk_address(&chunk.address, &chunk.bytes).unwrap();
        }
    }

    #[test]
    fn verify_chunk_address_rejects_tampered_bytes() {
        let bytes = fixed_input(8 * 1024);
        let (chunks, _) = encrypt(&bytes).unwrap();
        let chunk = &chunks[0];
        let mut tampered = chunk.bytes.clone();
        tampered[0] ^= 0x01;
        let err = verify_chunk_address(&chunk.address, &tampered).unwrap_err();
        assert!(matches!(err, StorageError::AddressMismatch { .. }));
    }

    #[test]
    fn data_map_round_trip_via_cbor() {
        let bytes = fixed_input(8 * 1024);
        let (_, dm) = encrypt(&bytes).unwrap();
        let cbor = crate::encoding::cbor_to_vec(&dm).unwrap();
        let back: DataMap = crate::encoding::cbor_from_slice(&cbor).unwrap();
        assert_eq!(back, dm);
    }

    #[test]
    fn data_map_exposes_addresses_in_order() {
        let bytes = fixed_input(50 * 1024);
        let (chunks, dm) = encrypt(&bytes).unwrap();
        let addrs = dm.chunk_addresses().unwrap();
        assert_eq!(addrs.len(), chunks.len());
        for (i, a) in addrs.iter().enumerate() {
            assert_eq!(a, &chunks[i].address);
        }
    }

    #[test]
    fn data_map_reports_original_size() {
        let bytes = fixed_input(7 * 1024);
        let (_, dm) = encrypt(&bytes).unwrap();
        assert_eq!(dm.original_size().unwrap(), 7 * 1024);
    }

    #[test]
    fn aead_then_selfencrypt_breaks_convergence() {
        // Same plaintext through two different AEAD keys must produce
        // different chunk addresses. Without AEAD, self-encryption is
        // deterministic → same chunks → convergence (a privacy hole).
        use crate::crypto::aead::{seal, AeadKey};
        let pt = b"identical plaintext across users".repeat(200);
        let key_a = AeadKey::from_bytes([1u8; 32]);
        let key_b = AeadKey::from_bytes([2u8; 32]);
        let ct_a = seal(&key_a, &pt, b"").unwrap();
        let ct_b = seal(&key_b, &pt, b"").unwrap();
        let (chunks_a, _) = encrypt(&ct_a).unwrap();
        let (chunks_b, _) = encrypt(&ct_b).unwrap();
        // No chunk address from set A should appear in set B.
        let set_a: std::collections::HashSet<_> =
            chunks_a.iter().map(|c| c.address.clone()).collect();
        for c in &chunks_b {
            assert!(
                !set_a.contains(&c.address),
                "convergence leak: identical chunk across users"
            );
        }
    }
}
