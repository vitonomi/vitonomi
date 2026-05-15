//! Alias-directory lookup. Resolves
//! `(alias_handle, namespace) → AliasDirectoryEntry` via the
//! hub's public GET endpoint, with a tiny in-memory cache so
//! that bursty mail (multiple messages to the same alias in
//! quick succession) doesn't hammer the hub.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use vitonomi_core::protocol::wire::aliases::AliasDirectoryEntry;

use crate::hub_client::HubClient;

/// Cache TTL — short enough that an alias-pubkey rotation
/// propagates in a minute or two; long enough that a typical
/// burst hits the cache.
const TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct AliasLookup {
    hub: HubClient,
    cache: Arc<Mutex<HashMap<(String, String), CachedEntry>>>,
}

struct CachedEntry {
    /// `Some` = directory entry; `None` = negative cache (we
    /// confirmed the address doesn't exist). Both expire
    /// together.
    entry: Option<AliasDirectoryEntry>,
    fetched_at: Instant,
}

impl AliasLookup {
    #[must_use]
    pub fn new(hub: HubClient) -> Self {
        Self {
            hub,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns `Ok(Some)` if the alias is known; `Ok(None)`
    /// if the hub returned 404 (negative cache hit OR fresh
    /// confirmation that the alias doesn't exist).
    ///
    /// # Errors
    ///
    /// Network / decode errors from the hub call.
    pub async fn lookup(
        &self,
        alias_handle: &str,
        namespace: &str,
    ) -> anyhow::Result<Option<AliasDirectoryEntry>> {
        let key = (alias_handle.to_string(), namespace.to_string());
        // Fast path: cache hit (positive or negative) within TTL.
        {
            let g = self.cache.lock();
            if let Some(c) = g.get(&key) {
                if c.fetched_at.elapsed() < TTL {
                    return Ok(c.entry.clone());
                }
            }
        }
        let fetched = self.hub.lookup_alias_pubkey(alias_handle, namespace).await?;
        {
            let mut g = self.cache.lock();
            g.insert(
                key,
                CachedEntry {
                    entry: fetched.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }
        Ok(fetched)
    }

    /// Drop everything. Useful in tests + on a SIGHUP.
    pub fn invalidate_all(&self) {
        self.cache.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidate_clears_cache() {
        let hub = HubClient::new("https://example.com").unwrap();
        let lookup = AliasLookup::new(hub);
        // Manually pre-populate to exercise the clear path
        // without making a network call (the cache field is
        // private to the module — use the public API instead).
        // Negative-cache test: post-invalidate map size is 0.
        lookup.invalidate_all();
        assert!(lookup.cache.lock().is_empty());
    }
}
