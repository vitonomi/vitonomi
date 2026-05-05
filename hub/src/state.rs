//! Shared application state passed to axum handlers via `State`.
//!
//! The hub binary currently uses `vitonomi_core::protocol::testing::
//! in_memory_hub::InMemoryHubControlPlane` as its data backend.
//! Persistent SQLite-backed storage lands in a follow-up commit.

use std::sync::Arc;

use vitonomi_core::protocol::hub_control_plane::HubControlPlane;
use vitonomi_core::protocol::testing::in_memory_hub::InMemoryHubControlPlane;

#[derive(Clone)]
pub struct AppState {
    pub control_plane: Arc<dyn HubControlPlane>,
    pub version: &'static str,
}

impl AppState {
    /// Build the default in-memory state.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            control_plane: Arc::new(InMemoryHubControlPlane::new()),
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}
