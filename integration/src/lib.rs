//! Shared end-to-end test harness for vitonomi integration tests.
//!
//! Every integration test in this crate boots an in-memory hub on
//! port 0, registers an admin via the CLI library entrypoints, and
//! optionally accepts one or more vaults. The duplicated bootstrap
//! code that previously lived in each test file is centralised in
//! [`harness`].

pub mod harness;
