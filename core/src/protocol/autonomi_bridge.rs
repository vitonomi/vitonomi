//! Stub trait for the future Autonomi 2.0 bridge.
//!
//! The mini-MVP doesn't replicate chunks anywhere except a vault's
//! local disk; this trait exists so the seam is locked at the
//! current phase. v1.1 wires it to the upstream `autonomi` crate.

use async_trait::async_trait;

use crate::errors::CoreError;

/// Content-addressed chunk identifier.
///
/// The byte layout matches Autonomi's chunk-address hash function
/// (BLAKE3 per upstream); `core` defers concrete implementation
/// until chunk-store work begins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ChunkAddress(pub [u8; 32]);

#[async_trait]
pub trait AutonomiBridge: Send + Sync {
    /// Push a batch of chunks to the Autonomi network.
    async fn push_chunks(&self, addresses: &[ChunkAddress]) -> Result<(), CoreError>;
    /// Fetch a single chunk by address.
    async fn fetch_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError>;
}

/// MVP no-op implementation. Returns a typed error if the data layer
/// somehow ends up calling it before v1.1.
pub struct NoopAutonomiBridge;

#[async_trait]
impl AutonomiBridge for NoopAutonomiBridge {
    async fn push_chunks(&self, _addresses: &[ChunkAddress]) -> Result<(), CoreError> {
        Err(CoreError::Network(crate::errors::NetworkError::Connect(
            "Autonomi bridge is a v1.1 feature".into(),
        )))
    }
    async fn fetch_chunk(&self, _address: &ChunkAddress) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::Network(crate::errors::NetworkError::Connect(
            "Autonomi bridge is a v1.1 feature".into(),
        )))
    }
}
