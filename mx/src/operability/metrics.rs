//! Per-base-domain counters. Keyed by the configured base
//! (e.g. `vito.gg` or `inbox.example.com`); never by
//! `(alias, base)` — a per-alias key would leak the relay's
//! tenant list to anyone scraping the metrics endpoint.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct PerBaseCounters {
    /// Number of inbound messages successfully accepted +
    /// pushed to the hub.
    pub accepted: u64,
    /// Number of inbound messages dropped because the recipient
    /// alias is unknown (silent-drop on missing directory entry).
    /// Counted but never logged with the address.
    pub silent_dropped: u64,
    /// Number of bytes accepted (post-DATA, pre-encryption).
    /// Coarse-grained — operator can correlate to relay sizing.
    pub bytes_accepted: u64,
    /// Number of sessions that aborted with an internal error
    /// (TLS, mailin-embedded, hub-push transport, …).
    pub session_aborts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    pub per_base: HashMap<String, PerBaseCounters>,
}

/// Process-wide counter sink. Cheap to clone (`Arc`-wrapped);
/// safe to share across SMTP sessions.
#[derive(Default, Clone)]
pub struct Metrics {
    inner: Arc<Mutex<MetricsSnapshot>>,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the accepted counter for `base_domain`. The
    /// `base_domain` value is the relay's configured base, NOT
    /// the recipient address — never log the recipient at the
    /// call site.
    pub fn record_accepted(&self, base_domain: &str, bytes: u64) {
        let mut g = self.inner.lock();
        let c = g.per_base.entry(base_domain.to_string()).or_default();
        c.accepted += 1;
        c.bytes_accepted += bytes;
    }

    pub fn record_silent_drop(&self, base_domain: &str) {
        let mut g = self.inner.lock();
        let c = g.per_base.entry(base_domain.to_string()).or_default();
        c.silent_dropped += 1;
    }

    pub fn record_session_abort(&self, base_domain: &str) {
        let mut g = self.inner.lock();
        let c = g.per_base.entry(base_domain.to_string()).or_default();
        c.session_aborts += 1;
    }

    /// Snapshot for tests / `vitonomi-mx status` / future
    /// metrics-endpoint exposure.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.inner.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_aggregate_per_base_only_never_per_alias() {
        // Three sends to two different aliases under the same
        // base. The counter sink only sees the base; tenant
        // identity is never passed in.
        let m = Metrics::new();
        m.record_accepted("vito.gg", 1024);
        m.record_accepted("vito.gg", 2048);
        m.record_accepted("vito.gg", 512);
        let snap = m.snapshot();
        assert_eq!(snap.per_base.len(), 1);
        let c = &snap.per_base["vito.gg"];
        assert_eq!(c.accepted, 3);
        assert_eq!(c.bytes_accepted, 1024 + 2048 + 512);
    }

    #[test]
    fn metrics_silent_drop_is_separately_counted() {
        let m = Metrics::new();
        m.record_accepted("vito.gg", 100);
        m.record_silent_drop("vito.gg");
        m.record_silent_drop("vito.gg");
        let c = &m.snapshot().per_base["vito.gg"];
        assert_eq!(c.accepted, 1);
        assert_eq!(c.silent_dropped, 2);
    }

    #[test]
    fn metrics_separate_bases_isolated() {
        let m = Metrics::new();
        m.record_accepted("vito.gg", 1);
        m.record_accepted("inbox.example.com", 2);
        let snap = m.snapshot();
        assert_eq!(snap.per_base["vito.gg"].accepted, 1);
        assert_eq!(snap.per_base["inbox.example.com"].accepted, 1);
    }

    #[test]
    fn metrics_snapshot_keys_are_only_base_domains() {
        // Pin the privacy invariant: snapshot keys must look
        // like base domains, never per-alias addresses.
        let m = Metrics::new();
        m.record_accepted("vito.gg", 1);
        for key in m.snapshot().per_base.keys() {
            assert!(
                !key.contains('@'),
                "metric key {key:?} contains '@' — looks like a per-alias \
                 entry, which violates the per-base-only invariant"
            );
        }
    }
}
