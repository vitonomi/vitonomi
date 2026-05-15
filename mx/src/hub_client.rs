//! HTTP client for the relay → hub control-plane surface.
//!
//! Wraps `reqwest` with rustls-tls (no system-trust-store
//! shenanigans). Two operations Slice 7 needs:
//!
//! 1. `lookup_alias_pubkey(alias_handle, namespace)` — public
//!    GET against `/v1/aliases/directory/{alias}/{namespace}`.
//! 2. `relay_push_inbound(SignedRelayPush)` — POST to
//!    `/v1/mx/messages` with a relay-signed envelope.
//!
//! We do NOT hold a hub session token — the relay authenticates
//! per-push via the embedded `sig_relay`. The hub looks up the
//! relay's pubkey via `relay_id` and verifies before queueing.

use std::time::Duration;

use anyhow::{anyhow, Context as _};
use reqwest::Client;

use vitonomi_core::protocol::wire::aliases::AliasDirectoryEntry;
use vitonomi_core::protocol::wire::relay_push::{RelayPushAck, SignedRelayPush};

/// HTTP client for the hub. Cheap to clone (`reqwest::Client`
/// is internally `Arc`-wrapped).
#[derive(Clone)]
pub struct HubClient {
    base_url: String,
    inner: Client,
}

impl HubClient {
    /// Build a client pointing at `base_url`. The base URL
    /// includes scheme + host (+ optional port), e.g.
    /// `https://hub.vitonomi.com`.
    ///
    /// # Errors
    ///
    /// `reqwest` builder failure (rare; usually only on
    /// missing TLS backend).
    pub fn new(base_url: impl Into<String>) -> anyhow::Result<Self> {
        let inner = Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(15))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            inner,
        })
    }

    /// Public lookup. Returns `Ok(None)` for 404.
    ///
    /// # Errors
    ///
    /// Network / serde failures other than 404.
    pub async fn lookup_alias_pubkey(
        &self,
        alias_handle: &str,
        namespace: &str,
    ) -> anyhow::Result<Option<AliasDirectoryEntry>> {
        let url = format!(
            "{}/v1/aliases/directory/{}/{}",
            self.base_url,
            urlencode(alias_handle),
            urlencode(namespace)
        );
        let resp = self.inner.get(&url).send().await.context("GET")?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(anyhow!(
                "alias lookup {url} returned status {}",
                resp.status()
            ));
        }
        let entry: AliasDirectoryEntry = resp
            .json()
            .await
            .context("decode AliasDirectoryEntry JSON")?;
        Ok(Some(entry))
    }

    /// Push a signed envelope to the hub's relay endpoint.
    ///
    /// # Errors
    ///
    /// Network / serde failures. A `received: false` ack from
    /// the hub (silent-drop on unknown alias) is returned as
    /// `Ok` — the caller increments the relay's silent-drop
    /// counter without logging the address.
    pub async fn relay_push_inbound(
        &self,
        push: &SignedRelayPush,
    ) -> anyhow::Result<RelayPushAck> {
        let url = format!("{}/v1/mx/messages", self.base_url);
        let resp = self
            .inner
            .post(&url)
            .json(push)
            .send()
            .await
            .context("POST /v1/mx/messages")?;
        if !resp.status().is_success() {
            return Err(anyhow!("relay_push_inbound returned {}", resp.status()));
        }
        let ack: RelayPushAck = resp.json().await.context("decode RelayPushAck JSON")?;
        Ok(ack)
    }
}

/// Tiny URL-component encoder. Handles the chars our wire
/// values can contain (alias-handles + dotted domains); good
/// enough for the relay's two GET paths.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_passes_alphanumerics_and_safe_punctuation() {
        assert_eq!(urlencode("inbox-demo"), "inbox-demo");
        assert_eq!(urlencode("inbox-demo.vito.gg"), "inbox-demo.vito.gg");
        assert_eq!(urlencode("netflix"), "netflix");
    }

    #[test]
    fn urlencode_escapes_at_and_other_unsafe_chars() {
        assert_eq!(urlencode("a@b"), "a%40b");
        assert_eq!(urlencode("a b"), "a%20b");
    }

    #[test]
    fn new_strips_trailing_slash() {
        let c = HubClient::new("https://hub.example.com/").unwrap();
        assert!(!c.base_url.ends_with('/'));
    }
}
