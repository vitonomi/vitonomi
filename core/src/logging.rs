//! `tracing` facade. Every binary calls [`init`] (or [`init_for_tests`]
//! in tests) once at startup. Thereafter all logs go through
//! `tracing::info!` / `tracing::error!` / etc.

use std::sync::OnceLock;

use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

static INIT: OnceLock<()> = OnceLock::new();

/// Initialise structured JSON logging. Honours `RUST_LOG` /
/// `VITONOMI_LOG` env-filter syntax.
///
/// Idempotent: subsequent calls are no-ops.
pub fn init() {
    INIT.get_or_init(|| {
        let filter = EnvFilter::try_from_env("VITONOMI_LOG")
            .or_else(|_| EnvFilter::try_from_env("RUST_LOG"))
            .unwrap_or_else(|_| EnvFilter::new("info"));
        let layer = fmt::layer()
            .json()
            .with_current_span(false)
            .with_span_list(false);
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .try_init();
    });
}

/// Initialise plain-text logging suitable for tests. No-op after first
/// call.
pub fn init_for_tests() {
    INIT.get_or_init(|| {
        let _ = tracing_subscriber::registry()
            .with(EnvFilter::new("debug"))
            .with(fmt::layer().with_test_writer())
            .try_init();
    });
}
