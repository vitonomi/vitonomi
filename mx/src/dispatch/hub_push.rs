//! Encrypt + sign + push one inbound message.
//!
//! Called from the SMTP handler's `data_end` callback once
//! the plaintext is fully accumulated in the encryptor stream.
//! Steps:
//!
//! 1. Resolve `(alias_handle, namespace) → (alias_id,
//!    alias_kem_pubkey)` via [`AliasLookup`]. On miss → silent
//!    drop; increment per-base-domain reject counter; the
//!    plaintext is dropped + zeroized.
//! 2. AEAD-seal the plaintext to the alias pubkey via
//!    [`vitonomi_core::crypto::alias_inbound::seal_to_alias`].
//! 3. Sign the resulting `SignedMxRelayPush` with the mx-relay's
//!    ML-DSA-65 secret key.
//! 4. POST `/v1/mx/messages`. Hub may also return
//!    `received: false` (defense in depth) — treat the same
//!    way: bump silent-drop counter, no log of the address.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;

use vitonomi_core::crypto::alias_inbound::seal_to_alias;
use vitonomi_core::crypto::pq::{ml_dsa_65_sign, MlDsa65Signature};
use vitonomi_core::protocol::wire::mx_relay_push::{MxRelayId, SignedMxRelayPush};

use crate::dispatch::alias_lookup::AliasLookup;
use crate::hub_client::HubClient;
use crate::identity::MxRelayIdentity;
use crate::operability::Metrics;

/// One-shot dispatch of an inbound mail. Returns `true` iff
/// the mail was queued at the hub; `false` iff it was silent-
/// dropped (unknown alias). Either way, the metrics are
/// updated under the mx-relay's configured base domain.
///
/// # Errors
///
/// Network / crypto failures other than silent-drop. Errors
/// here cause the SMTP session to log a session-abort metric;
/// the recipient address is NEVER part of the error path.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch(
    plaintext: Vec<u8>,
    alias_handle: &str,
    namespace: &str,
    base_domain: &str,
    mx_relay_id: MxRelayId,
    identity: &MxRelayIdentity,
    hub_client: &HubClient,
    alias_lookup: &AliasLookup,
    metrics: &Metrics,
) -> anyhow::Result<bool> {
    // 1. Look up the alias. Silent-drop on miss.
    let entry = match alias_lookup.lookup(alias_handle, namespace).await? {
        Some(e) => e,
        None => {
            metrics.record_silent_drop(base_domain);
            return Ok(false);
        }
    };

    // 2. AEAD-seal under the alias pubkey + (alias_id,
    //    received_at_ms) AAD binding.
    let received_at_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let plaintext_len = plaintext.len() as u64;
    let envelope = seal_to_alias(
        &entry.alias_kem_pubkey,
        entry.alias_id,
        received_at_ms,
        &plaintext,
    )
    .context("seal_to_alias")?;
    // The plaintext drops here — it's now AEAD-sealed inside
    // `envelope.aead_payload`.
    drop(plaintext);

    // 3. Build + sign the push.
    let mut push = SignedMxRelayPush {
        mx_relay_id,
        alias_directory_lookup: (alias_handle.to_string(), namespace.to_string()),
        envelope,
        server_received_at_ms: received_at_ms,
        sig_mx_relay: MlDsa65Signature(vec![]),
    };
    let signed_bytes = push.signed_bytes().context("signed_bytes")?;
    push.sig_mx_relay =
        ml_dsa_65_sign(&identity.secret, &signed_bytes).context("sign mx-relay push")?;

    // 4. POST.
    let ack = hub_client
        .mx_relay_push_inbound(&push)
        .await
        .context("mx_relay_push_inbound")?;
    if ack.received {
        metrics.record_accepted(base_domain, plaintext_len);
        Ok(true)
    } else {
        // Defense-in-depth silent-drop signal from the hub
        // (e.g. registry race). Same metric bucket as our
        // local lookup miss.
        metrics.record_silent_drop(base_domain);
        Ok(false)
    }
}
