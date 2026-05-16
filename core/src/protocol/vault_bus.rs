//! Trait abstraction over the vault ↔ hub streaming session.
//!
//! `WebSocketVaultBus` (in the `vault` crate) implements the real
//! transport via `tokio-tungstenite` + `rustls`. `InMemoryVaultBus`
//! (in [`super::testing`]) implements the same surface with
//! in-process channels for tests.
//!
//! A `Libp2pVaultBus` implementation will slot in here without
//! changing any caller once the libp2p-rs data plane lands.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::errors::CoreError;
use crate::protocol::wire::vault_bus::BusFrame;

/// A connected vault session. Drop the session to disconnect.
pub trait VaultSession: Send {
    /// Send a frame to the peer.
    fn send(&self, frame: BusFrame) -> Result<(), CoreError>;
    /// Close the session gracefully.
    fn close(&self);
}

/// One end of a vault-bus connection. Implementations differ by
/// transport (WebSocket today, libp2p-rs later, in-memory channels
/// in tests).
#[async_trait]
pub trait VaultBus: Send + Sync {
    /// Open a fresh outbound session. The returned session can be
    /// used to send frames; the receiver yields incoming frames.
    async fn connect(&self)
        -> Result<(Box<dyn VaultSession>, mpsc::Receiver<BusFrame>), CoreError>;
}
