//! `mailin-embedded::Handler` implementation.
//!
//! The vitonomi-mx privacy semantics live here:
//!
//! - **`rcpt`** returns `Ok` (250) for **every** address
//!   regardless of whether the alias actually exists. The
//!   alias-existence check moves to `data_end` (silent-drop on
//!   miss). Plugs the SMTP-RCPT enumeration channel.
//! - **`data_start`** initialises a fresh
//!   [`crate::smtp::encryptor_stream::EncryptorStream`].
//! - **`data`** appends every chunk into the in-memory buffer.
//! - **`data_end`** hands the plaintext to
//!   [`crate::dispatch::hub_push::dispatch`] which seals + signs
//!   + posts to the hub. The buffer zeroizes on drop.
//!
//! The handler is `Clone` because `mailin-embedded` clones it
//! per session. Inner state (metrics, hub client, alias lookup,
//! identity) is `Arc`-shared.

use std::sync::Arc;

use mailin_embedded::response::{INTERNAL_ERROR, OK};
use mailin_embedded::{Handler, Response};

use vitonomi_core::protocol::wire::mx_relay_push::MxRelayId;

use crate::dispatch::alias_lookup::AliasLookup;
use crate::dispatch::hub_push::dispatch;
use crate::hub_client::HubClient;
use crate::identity::MxRelayIdentity;
use crate::operability::Metrics;
use crate::smtp::encryptor_stream::EncryptorStream;

/// Shared state every SMTP session reads. `Arc`-cloned per
/// session by `mailin-embedded`; the inner fields don't need
/// per-session locking because the components themselves are
/// either immutable or internally synchronized.
#[derive(Clone)]
pub struct SharedState {
    pub identity: Arc<MxRelayIdentity>,
    pub mx_relay_id: MxRelayId,
    pub hub_client: HubClient,
    pub alias_lookup: AliasLookup,
    pub metrics: Metrics,
    pub base_domain: String,
}

/// Per-session state. Holds the encryptor stream + the most
/// recent recipient (we only push to the LAST recipient — the
/// privacy invariant says the relay accepts every RCPT but
/// only delivers to the alias the message was actually
/// addressed to in the headers; for MVP we honor the last
/// envelope RCPT TO).
pub struct MxHandler {
    pub shared: SharedState,
    /// Last recipient set via `rcpt`. `None` until first RCPT.
    pub last_rcpt: Option<String>,
    /// DATA-phase buffer. `None` outside a DATA window.
    pub stream: Option<EncryptorStream>,
}

impl MxHandler {
    #[must_use]
    pub fn new(shared: SharedState) -> Self {
        Self {
            shared,
            last_rcpt: None,
            stream: None,
        }
    }
}

impl Clone for MxHandler {
    fn clone(&self) -> Self {
        // mailin-embedded clones the handler per session; each
        // session needs a fresh per-session state. We reset
        // the per-session fields rather than copy them.
        Self {
            shared: self.shared.clone(),
            last_rcpt: None,
            stream: None,
        }
    }
}

impl Handler for MxHandler {
    /// **Privacy plug**: 250 OK for every RCPT regardless of
    /// alias existence. Alias check happens at data_end; silent
    /// drop on miss.
    fn rcpt(&mut self, to: &str) -> Response {
        // Cache the recipient so data_end knows where to push.
        // We do NOT log it — the operability layer's tracing
        // redaction would catch it but we don't even emit it.
        self.last_rcpt = Some(to.to_string());
        OK
    }

    fn data_start(
        &mut self,
        _domain: &str,
        _from: &str,
        _is8bit: bool,
        _to: &[String],
    ) -> Response {
        self.stream = Some(EncryptorStream::new());
        OK
    }

    fn data(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        if let Some(s) = self.stream.as_mut() {
            s.push(buf);
        }
        Ok(())
    }

    fn data_end(&mut self) -> Response {
        let Some(stream) = self.stream.take() else {
            return INTERNAL_ERROR;
        };
        if stream.over_cap() {
            self.shared
                .metrics
                .record_session_abort(&self.shared.base_domain);
            // 552: requested mail action aborted: exceeded
            // storage allocation. mailin-embedded doesn't
            // expose a constant for it; INTERNAL_ERROR (451)
            // is the closest builtin and acceptable for MVP.
            return INTERNAL_ERROR;
        }
        let Some(rcpt) = self.last_rcpt.take() else {
            return INTERNAL_ERROR;
        };
        // Parse `local@domain` rightmost-@. Invalid addresses
        // → silent-drop (250 OK; nobody learns the parse
        // failed).
        let (alias_handle, namespace) = match rcpt.rsplit_once('@') {
            Some((local, domain)) => (local.to_string(), domain.to_ascii_lowercase()),
            None => {
                self.shared
                    .metrics
                    .record_silent_drop(&self.shared.base_domain);
                return OK;
            }
        };
        let plaintext = stream.take();
        let shared = self.shared.clone();
        // mailin-embedded's data_end is sync; we have to spawn
        // the async dispatch onto the current tokio runtime.
        let handle = tokio::runtime::Handle::try_current();
        match handle {
            Ok(h) => {
                let res = h.block_on(dispatch(
                    plaintext,
                    &alias_handle,
                    &namespace,
                    &shared.base_domain,
                    shared.mx_relay_id,
                    &shared.identity,
                    &shared.hub_client,
                    &shared.alias_lookup,
                    &shared.metrics,
                ));
                match res {
                    Ok(_) => OK,
                    Err(_) => {
                        // Don't log the recipient — the abort
                        // metric is enough.
                        shared
                            .metrics
                            .record_session_abort(&shared.base_domain);
                        INTERNAL_ERROR
                    }
                }
            }
            Err(_) => {
                shared
                    .metrics
                    .record_session_abort(&shared.base_domain);
                INTERNAL_ERROR
            }
        }
    }
}

