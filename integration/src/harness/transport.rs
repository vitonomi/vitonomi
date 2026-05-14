//! Instrumented decorators around `ChunkTransport` used by Phase 6
//! tests to assert browse / search / metadata-only edits never
//! fetch (or upload) body chunks.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use vitonomi_core::crypto::selfencrypt::Chunk;
use vitonomi_core::errors::CoreError;
use vitonomi_core::protocol::autonomi_bridge::ChunkAddress;
use vitonomi_core::record::record_store::ChunkTransport;

/// One recorded transport operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpEvent {
    /// `put_chunks` was called with `chunk_count` chunks.
    Put { chunk_count: usize },
    /// `get_chunk` was called for the given address.
    Get { address: [u8; 32] },
}

/// Decorator over any `ChunkTransport` that records every
/// `put_chunks` / `get_chunk` call into a shared event log. Tests
/// snapshot the log via [`CountingChunkTransport::events`] and
/// assert about its contents (e.g. zero `Get` events during a
/// metadata-only browse).
pub struct CountingChunkTransport<T: ChunkTransport + ?Sized> {
    inner: Arc<T>,
    events: Arc<Mutex<Vec<OpEvent>>>,
}

impl<T: ChunkTransport + ?Sized> CountingChunkTransport<T> {
    pub fn new(inner: Arc<T>) -> Self {
        Self {
            inner,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Snapshot of every operation recorded so far.
    pub fn events(&self) -> Vec<OpEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Drop every recorded event. Useful for "do step 1, reset
    /// counter, then assert step 2 fetched zero chunks" assertions.
    pub fn reset(&self) {
        self.events.lock().unwrap().clear();
    }

    /// Convenience: count of `Get` events recorded so far.
    pub fn get_count(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, OpEvent::Get { .. }))
            .count()
    }

    /// Convenience: total chunk count across every `Put` event.
    pub fn put_chunk_total(&self) -> usize {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|e| match e {
                OpEvent::Put { chunk_count } => *chunk_count,
                OpEvent::Get { .. } => 0,
            })
            .sum()
    }
}

#[async_trait]
impl<T: ChunkTransport + ?Sized> ChunkTransport for CountingChunkTransport<T> {
    async fn put_chunks(&self, chunks: &[Chunk]) -> Result<(), CoreError> {
        let res = self.inner.put_chunks(chunks).await;
        if res.is_ok() {
            self.events.lock().unwrap().push(OpEvent::Put {
                chunk_count: chunks.len(),
            });
        }
        res
    }

    async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError> {
        let res = self.inner.get_chunk(address).await;
        if res.is_ok() {
            self.events
                .lock()
                .unwrap()
                .push(OpEvent::Get { address: address.0 });
        }
        res
    }
}
