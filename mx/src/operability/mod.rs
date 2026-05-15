//! Operability surface — metrics + a tracing layer that
//! redacts sender / recipient / subject / body fields from
//! third-party log lines.
//!
//! **Privacy invariant**: every metric counter is keyed by the
//! relay's configured base domain, never by per-alias. Per-alias
//! counters would let an observer of the metrics endpoint
//! enumerate which aliases are receiving mail and at what rate.

pub mod metrics;
pub mod tracing_redact;

pub use metrics::{Metrics, MetricsSnapshot};
