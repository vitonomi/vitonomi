//! Shared application state passed to axum handlers via `State`.
//!
//! The hub binary currently uses `vitonomi_core::protocol::testing::
//! in_memory_hub::InMemoryHubControlPlane` as its data backend.
//! Persistent SQLite-backed storage lands in a follow-up commit.

use std::sync::Arc;

use vitonomi_core::protocol::hub_control_plane::HubControlPlane;
use vitonomi_core::protocol::testing::in_memory_hub::InMemoryHubControlPlane;
use vitonomi_core::protocol::wire::bootstrap::BootstrapPolicy;

#[derive(Clone)]
pub struct AppState {
    pub control_plane: Arc<dyn HubControlPlane>,
    pub version: &'static str,
}

impl AppState {
    /// Build the default in-memory state with the default
    /// `BootstrapPolicy::SingleUser`.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::in_memory_with_policy(BootstrapPolicy::default())
    }

    /// Build in-memory state with a specific bootstrap policy. Used
    /// by the production `start` path to wire the operator-configured
    /// policy in, and by tests that need allowlist / open.
    #[must_use]
    pub fn in_memory_with_policy(policy: BootstrapPolicy) -> Self {
        Self {
            control_plane: Arc::new(InMemoryHubControlPlane::new().with_bootstrap_policy(policy)),
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}
