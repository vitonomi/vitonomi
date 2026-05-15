//! Wire types for the relay → hub push surface and the
//! deploy-time relay-identity registration.

use serde::{Deserialize, Serialize};

use crate::crypto::alias_inbound::AliasInboundCiphertext;
use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65Signature};
use crate::encoding::cbor_to_vec;
use crate::errors::ProtocolError;

/// Opaque 16-byte identifier the hub assigns to a registered
/// relay at `POST /v1/admin/relays`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelayId(pub [u8; 16]);

/// One inbound mail pushed by `vitonomi-mx` to the hub.
///
/// `sig_relay` covers the deterministic CBOR of the (relay_id,
/// alias_directory_lookup, envelope, server_received_at_ms)
/// quadruple — the hub verifies before queueing so a forged
/// push from anyone other than the registered relay is
/// rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRelayPush {
    pub relay_id: RelayId,
    /// `(alias_handle, namespace)` — the alias the message is
    /// addressed to. Hub uses this to route the envelope to the
    /// right per-alias inbound queue.
    pub alias_directory_lookup: (String, String),
    pub envelope: AliasInboundCiphertext,
    pub server_received_at_ms: u64,
    pub sig_relay: MlDsa65Signature,
}

/// Hub response to a relay push. `received: false` is the
/// silent-drop signal the relay translates back to its
/// per-base-domain reject counter — the hub still 200s, no log
/// line carries the alias address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPushAck {
    pub received: bool,
}

/// Body of `POST /v1/admin/relays`. Operator-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRelayRequest {
    pub relay_pubkey: MlDsa65PublicKey,
    /// Allowed namespaces this relay may push for. Hosted
    /// relay registers `["vito.gg"]` (every subdomain under
    /// the configured base); tenant relays register specific
    /// custom domains. Wildcards are not interpreted by the
    /// hub — exact-match only.
    pub allowed_namespaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRelayResponse {
    pub relay_id: RelayId,
}

impl SignedRelayPush {
    /// The deterministic CBOR bytes [`Self::sig_relay`] signs
    /// over. Excludes the signature itself so the recipient can
    /// recompute and verify.
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` on encode failure.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        // Pack the to-be-signed fields into a tuple so the order
        // is fixed regardless of struct field order.
        let tuple = (
            &self.relay_id,
            &self.alias_directory_lookup,
            &self.envelope,
            self.server_received_at_ms,
        );
        cbor_to_vec(&tuple)
    }
}
