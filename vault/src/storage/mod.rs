//! Vault chunk-storage backends.
//!
//! `SqliteVaultStorage` (the production impl) is built on two
//! cooperating pieces:
//!
//! - `fs_chunk_dir` — Autonomi-format chunk bytes on a sharded
//!   filesystem (`<data_dir>/chunks/<aa>/<full-address>.chunk`).
//! - `sqlite` — chunk metadata (`address`, `owner_user_id`, `size`,
//!   `created_at_ms`, `replicated_to_peers`) in
//!   `<data_dir>/index.sqlite`.
//!
//! The split lets us serve `has_chunk` / `usage_by_user` /
//! `list_chunks_for_owner` without touching the filesystem, while
//! the actual chunk bytes (which can be megabytes each) stay outside
//! the database.

pub mod fs_chunk_dir;
pub mod sqlite;

pub use sqlite::SqliteVaultStorage;
