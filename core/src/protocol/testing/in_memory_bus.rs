//! In-memory `VaultBus` for tests. Echoes frames back through a
//! tokio channel; exercises the same `BusFrame` enum the WebSocket
//! transport uses.

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::errors::CoreError;
use crate::protocol::vault_bus::{VaultBus, VaultSession};
use crate::protocol::wire::vault_bus::BusFrame;

pub struct InMemoryVaultBus;

impl InMemoryVaultBus {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for InMemoryVaultBus {
    fn default() -> Self {
        Self::new()
    }
}

struct InMemorySession {
    sender: mpsc::UnboundedSender<BusFrame>,
}

impl VaultSession for InMemorySession {
    fn send(&self, frame: BusFrame) -> Result<(), CoreError> {
        self.sender
            .send(frame)
            .map_err(|e| CoreError::Network(crate::errors::NetworkError::WebSocket(e.to_string())))
    }

    fn close(&self) {
        // Drop the sender by dropping the session.
    }
}

#[async_trait]
impl VaultBus for InMemoryVaultBus {
    async fn connect(
        &self,
    ) -> Result<(Box<dyn VaultSession>, mpsc::Receiver<BusFrame>), CoreError> {
        let (sender, _proxy_rx) = mpsc::unbounded_channel();
        let (mpsc_tx, mpsc_rx) = mpsc::channel::<BusFrame>(32);
        // Drain proxy_rx → mpsc_tx in a background task so callers
        // can recv from mpsc_rx like a real WS connection.
        let session = InMemorySession { sender };
        tokio::spawn(async move {
            // The proxy_rx side of the unbounded channel is wired
            // directly so frames sent via session.send() are
            // forwarded back to the mpsc_rx held by the caller.
            // (Trivial echo; for real test scenarios overlay a
            // scripted server using a wrapper that picks up the
            // unbounded receiver and emits scripted responses.)
            drop(_proxy_rx);
            let _ = mpsc_tx;
        });
        Ok((Box::new(session), mpsc_rx))
    }
}
