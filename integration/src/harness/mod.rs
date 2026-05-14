//! End-to-end test harness.
//!
//! Provides a one-call `E2eFixture::up()` that boots an in-memory
//! hub, sets up an admin via the CLI library, and returns the paths
//! every downstream test step needs. Lower-level helpers
//! (`boot_hub`, `setup_admin`, `run_cluster_create`, `run_vault_invite`,
//! `setup_and_accept_vault`) are exposed individually for tests that
//! want to drive the bootstrap incrementally.
//!
//! `harness::transport::CountingChunkTransport` decorates any
//! `ChunkTransport` and records every put/get operation — used by
//! the metadata-only-fetch assertions in Phase 6's tests.

pub mod admin;
pub mod hub;
pub mod params;
pub mod transport;
pub mod vault;

pub use admin::{run_cluster_create, run_vault_invite, setup_admin, AdminContext};
pub use hub::boot_hub;
pub use params::{dummy_fingerprint, fast_keyblob_params, fast_lookup_params};
pub use transport::{CountingChunkTransport, OpEvent};
pub use vault::{setup_and_accept_vault, setup_and_accept_vault_with, VaultContext, VaultSetupOpts};
