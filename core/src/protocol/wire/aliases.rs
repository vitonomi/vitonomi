//! Wire types for the alias-directory + per-alias inbox surface.

use serde::{Deserialize, Serialize};

use crate::crypto::alias_inbound::AliasInboundCiphertext;
use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65Signature, MlKem768PublicKey};
use crate::encoding::cbor_to_vec;
use crate::errors::ProtocolError;
use crate::record::RecordId;

/// One row in the public alias directory. Keyed server-side by
/// `(alias_handle, namespace)`. **Username never appears as
/// either component.**
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasDirectoryEntry {
    pub alias_handle: String,
    /// Full domain (e.g. `inbox-demo.vito.gg` or `example.com`).
    pub namespace: String,
    /// The 16-byte hub-side identifier the mx relay uses to push
    /// inbound mail into this alias's inbound queue.
    pub alias_id: RecordId,
    /// ML-KEM-768 pubkey the mx relay encrypts inbound mail to.
    pub alias_kem_pubkey: MlKem768PublicKey,
    /// User identity pubkey that signed `sig_user`.
    pub user_identity_pubkey: MlDsa65PublicKey,
    /// User signature over the deterministic CBOR of all the
    /// preceding fields. Lets a fetcher verify the entry wasn't
    /// substituted by a malicious hub.
    pub sig_user: MlDsa65Signature,
}

impl AliasDirectoryEntry {
    /// The deterministic CBOR bytes the user signs. Identical
    /// recipe on both the client (which produces `sig_user`) and
    /// the hub (which verifies it on `POST /v1/aliases/directory`).
    /// Tuple order is fixed at `(alias_handle, namespace, alias_id,
    /// alias_kem_pubkey, user_identity_pubkey)` — anything more
    /// becomes a wire-format change.
    ///
    /// # Errors
    ///
    /// `ProtocolError::Cbor` on encode failure.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let tuple = (
            &self.alias_handle,
            &self.namespace,
            &self.alias_id,
            &self.alias_kem_pubkey,
            &self.user_identity_pubkey,
        );
        cbor_to_vec(&tuple)
    }
}

/// One inbound envelope in the per-alias FIFO. Hub stores
/// these verbatim; the user's client AEAD-opens and merges
/// into their own `AliasMessage` snapshot at fetch time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundEnvelope {
    /// Monotonic per-alias sequence — used by the client's
    /// `?since=<seq>` cursor.
    pub seq: u64,
    pub alias_id: RecordId,
    pub envelope: AliasInboundCiphertext,
    pub server_received_at_ms: u64,
}
