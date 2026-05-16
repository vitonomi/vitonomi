//! Wire types for the `vitonomi-mx` (mx) relay → hub push surface
//! and the deploy-time mx-relay identity registration.

use serde::{Deserialize, Serialize};

use crate::crypto::alias_inbound::AliasInboundCiphertext;
use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65Signature};
use crate::encoding::cbor_to_vec;
use crate::errors::ProtocolError;

/// 16-byte identifier for a registered `vitonomi-mx` relay.
/// Deterministically derived from the mx relay's ML-DSA-65 pubkey via
/// BLAKE3-128, so both the relay and the hub compute the same id
/// without an extra round-trip. Carried in every
/// [`SignedMxRelayPush`] as a compact lookup key (~1900 bytes shorter
/// than the full pubkey).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MxRelayId(pub [u8; 16]);

impl MxRelayId {
    /// Derive the mx relay's identifier from its ML-DSA-65 pubkey.
    ///
    /// Truncates `BLAKE3(pubkey_bytes)` to 16 bytes. 128 bits is
    /// far more than enough collision resistance for the mx-relay
    /// directory — rotating the keypair yields a new id, which is
    /// the intended semantics (the rotated relay is a new
    /// principal from the hub's perspective).
    #[must_use]
    pub fn from_pubkey(pk: &crate::crypto::pq::MlDsa65PublicKey) -> Self {
        let hash = blake3::hash(pk.as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&hash.as_bytes()[..16]);
        Self(out)
    }
}

/// One inbound mail pushed by `vitonomi-mx` (the mx relay) to the
/// hub.
///
/// `sig_mx_relay` covers the deterministic CBOR of the (mx_relay_id,
/// alias_directory_lookup, envelope, server_received_at_ms)
/// quadruple — the hub verifies before queueing so a forged push
/// from anyone other than the registered mx relay is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMxRelayPush {
    pub mx_relay_id: MxRelayId,
    /// `(alias_handle, namespace)` — the alias the message is
    /// addressed to. Hub uses this to route the envelope to the
    /// right per-alias inbound queue.
    pub alias_directory_lookup: (String, String),
    pub envelope: AliasInboundCiphertext,
    pub server_received_at_ms: u64,
    pub sig_mx_relay: MlDsa65Signature,
}

/// Hub response to an mx-relay push. `received: false` is the
/// silent-drop signal the mx relay translates back to its
/// per-base-domain reject counter — the hub still 200s, no log
/// line carries the alias address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxRelayPushAck {
    pub received: bool,
}

/// Body of `POST /v1/admin/mx-relays`. Admin-only. Returns
/// `204 No Content` on success — the mx relay's [`MxRelayId`] is
/// derivable locally via [`MxRelayId::from_pubkey`], so the hub
/// doesn't echo it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterMxRelayRequest {
    pub mx_relay_pubkey: MlDsa65PublicKey,
    /// Allowed namespaces this mx relay may push for. Hosted
    /// mx relay registers `["vito.gg"]` (every subdomain under
    /// the configured base); tenant mx relays register specific
    /// custom domains. Wildcards are not interpreted by the
    /// hub — exact-match only.
    pub allowed_namespaces: Vec<String>,
}

impl SignedMxRelayPush {
    /// The deterministic CBOR bytes [`Self::sig_mx_relay`] signs
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
            &self.mx_relay_id,
            &self.alias_directory_lookup,
            &self.envelope,
            self.server_received_at_ms,
        );
        cbor_to_vec(&tuple)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_dsa_65_keypair;

    #[test]
    fn mx_relay_id_from_pubkey_is_deterministic() {
        let kp = ml_dsa_65_keypair().unwrap();
        let a = MxRelayId::from_pubkey(&kp.public);
        let b = MxRelayId::from_pubkey(&kp.public);
        assert_eq!(a, b, "same pubkey must yield same id");
    }

    #[test]
    fn mx_relay_id_from_pubkey_differs_for_different_pubkeys() {
        let a_kp = ml_dsa_65_keypair().unwrap();
        let b_kp = ml_dsa_65_keypair().unwrap();
        let a = MxRelayId::from_pubkey(&a_kp.public);
        let b = MxRelayId::from_pubkey(&b_kp.public);
        assert_ne!(a, b, "distinct pubkeys must yield distinct ids");
    }
}
