//! libp2p data-plane wire types.
//!
//! Single request-response protocol `/vitonomi/chunks/1.0.0`. The
//! vault verifies the user signature on every request and dispatches
//! to its `SqliteVaultStorage` after a freshness + admin-chain
//! user-active check.
//!
//! Optional `/vitonomi/auth/1.0.0` types ([`AuthFrame`] / [`AuthAck`])
//! are defined for a future session-handle path (v1.1 — amortises the
//! ML-DSA signature cost across many ops). Today only the
//! per-op-signature variant is wired.
//!
//! All frames are deterministic CBOR (consistent with the existing
//! `BusFrame` style under `wire::vault_bus`).

use serde::{Deserialize, Serialize};

use crate::crypto::pq::{MlDsa65PublicKey, MlDsa65Signature};
use crate::protocol::autonomi_bridge::ChunkAddress;
use crate::protocol::wire::rendezvous::RendezvousToken;
use crate::types::{FormatVersion, UserId};

// ─── /vitonomi/auth/1.0.0 ────────────────────────────────────────────

/// Request body on the auth stream. The vault verifies:
/// - the hub signed `token` and it's not expired,
/// - `user_id` matches the token,
/// - the client signed `(token.bytes || fresh_challenge_nonce)` with
///   the identity sk corresponding to `user_identity_pubkey`,
/// - `user_identity_pubkey` matches the hub-recorded identity pubkey
///   for `(cluster_id, user_id)` (queried via
///   `HubControlPlane::get_user_identity_pubkey`),
/// - `user_id` is still active per the latest admin chain entry the
///   vault has on disk.
///
/// On success the vault mints a 32-byte random `session_handle` and
/// caches `(handle → SessionContext{user_id, peer_id, expires_at})`
/// in-process. The handle stamps every subsequent
/// [`ChunkOpRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFrame {
    pub format_version: FormatVersion,
    pub token: RendezvousToken,
    pub user_id: UserId,
    pub user_identity_pubkey: MlDsa65PublicKey,
    /// 32-byte random nonce the client picks. The vault re-uses it as
    /// a freshness witness in `auth_signed_bytes` below.
    #[serde(with = "serde_bytes")]
    pub fresh_challenge_nonce: Vec<u8>,
    /// ML-DSA-65 by the user identity sk over
    /// `auth_signed_bytes(&token_signed_bytes, &fresh_challenge_nonce)`.
    pub sig_user: MlDsa65Signature,
}

/// Build the bytes the user signs for an [`AuthFrame`]. Stable
/// layout: 8-byte BE length prefix + token signed bytes + 8-byte BE
/// length prefix + fresh nonce.
#[must_use]
pub fn auth_signed_bytes(token_signed_bytes: &[u8], fresh_nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + token_signed_bytes.len() + 8 + fresh_nonce.len());
    out.extend_from_slice(b"vitauthv1");
    out.extend_from_slice(&(token_signed_bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(token_signed_bytes);
    out.extend_from_slice(&(fresh_nonce.len() as u64).to_be_bytes());
    out.extend_from_slice(fresh_nonce);
    out
}

/// Response on the auth stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAck {
    pub format_version: FormatVersion,
    /// Opaque 32-byte handle tying this libp2p peer + user to the
    /// session. Expires after `expires_at_ms`.
    #[serde(with = "serde_bytes")]
    pub session_handle: Vec<u8>,
    pub expires_at_ms: u64,
}

// ─── /vitonomi/chunks/1.0.0 ──────────────────────────────────────────

/// Per-request operation on a content-addressed chunk store.
/// Variants are wire-stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "op")]
pub enum ChunkOp {
    /// Put many chunks atomically (from the caller's POV; the vault
    /// processes them one by one). `addresses[i]` must equal
    /// `blake3(chunks[i])` or the vault rejects the whole request.
    Put {
        addresses: Vec<ChunkAddress>,
        #[serde(with = "serde_bytes_vec")]
        chunks: Vec<Vec<u8>>,
    },
    Get {
        address: ChunkAddress,
    },
    /// List every chunk address owned by the authed user. Used by
    /// recovery + admin tools, NOT by the steady-state read path
    /// (snapshot chain walking is preferred there).
    List,
    Delete {
        address: ChunkAddress,
    },
}

mod serde_bytes_vec {
    //! Serialize `Vec<Vec<u8>>` as a CBOR array of byte-strings.
    use serde::{Deserialize, Deserializer, Serialize as _, Serializer};

    pub fn serialize<S: Serializer>(value: &[Vec<u8>], ser: S) -> Result<S::Ok, S::Error> {
        let wrapped: Vec<serde_bytes::ByteBuf> = value
            .iter()
            .map(|v| serde_bytes::ByteBuf::from(v.clone()))
            .collect();
        wrapped.serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let wrapped: Vec<serde_bytes::ByteBuf> = Vec::deserialize(de)?;
        Ok(wrapped
            .into_iter()
            .map(serde_bytes::ByteBuf::into_vec)
            .collect())
    }
}

/// Request body for `/vitonomi/chunks/1.0.0`.
///
/// Self-contained: every request carries the (cluster_id, user_id)
/// pair plus an ML-DSA-65 signature over
/// [`chunk_op_signed_bytes`]. The vault verifies the sig against the
/// user identity pubkey (queried once from the hub and cached).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkOpRequest {
    pub format_version: FormatVersion,
    pub request_id: u64,
    pub cluster_id: crate::types::ClusterId,
    pub user_id: UserId,
    pub op: ChunkOp,
    pub created_at_ms: u64,
    /// ML-DSA-65 by the user identity sk over
    /// [`chunk_op_signed_bytes`].
    pub sig_user: MlDsa65Signature,
}

/// Build the bytes the user signs for a [`ChunkOpRequest`]. Stable
/// layout: ASCII magic + 1-byte format_version + 8-byte BE request_id
/// + cluster_id(32) + user_id(16) + 8-byte BE CBOR(op) length + CBOR(op)
/// + 8-byte BE created_at_ms.
///
/// # Errors
///
/// `ProtocolError::Cbor` if CBOR encoding of `op` fails.
pub fn chunk_op_signed_bytes(
    format_version: FormatVersion,
    request_id: u64,
    cluster_id: &crate::types::ClusterId,
    user_id: &UserId,
    op: &ChunkOp,
    created_at_ms: u64,
) -> Result<Vec<u8>, crate::errors::ProtocolError> {
    let op_cbor = crate::encoding::cbor_to_vec(op)?;
    let mut buf = Vec::with_capacity(9 + 1 + 8 + 32 + 16 + 8 + op_cbor.len() + 8);
    buf.extend_from_slice(b"vitchunk1");
    buf.push(format_version.as_u8());
    buf.extend_from_slice(&request_id.to_be_bytes());
    buf.extend_from_slice(&cluster_id.0);
    buf.extend_from_slice(&user_id.0);
    buf.extend_from_slice(&(op_cbor.len() as u64).to_be_bytes());
    buf.extend_from_slice(&op_cbor);
    buf.extend_from_slice(&created_at_ms.to_be_bytes());
    Ok(buf)
}

/// Response body for `/vitonomi/chunks/1.0.0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ChunkOpResponse {
    PutAck {
        request_id: u64,
        acked: Vec<ChunkAddress>,
        /// Per-chunk errors keyed by address. Empty on full success.
        errors: Vec<(ChunkAddress, String)>,
    },
    GetReply {
        request_id: u64,
        address: ChunkAddress,
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
        /// `false` means "vault has no chunk at this address";
        /// `bytes` is then empty.
        found: bool,
    },
    ListReply {
        request_id: u64,
        addresses: Vec<ChunkAddress>,
    },
    DeleteAck {
        request_id: u64,
        deleted: bool,
    },
    /// Reserved for transport-level + auth-level failures.
    Error {
        request_id: u64,
        code: u16,
        message: String,
    },
}

/// libp2p stream protocol names. Used by both vault and CLI.
pub const AUTH_PROTOCOL: &str = "/vitonomi/auth/1.0.0";
pub const CHUNKS_PROTOCOL: &str = "/vitonomi/chunks/1.0.0";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::ml_dsa_65_keypair;

    #[test]
    fn auth_signed_bytes_changes_with_every_field() {
        let a = auth_signed_bytes(b"token", b"nonce");
        let b = auth_signed_bytes(b"token2", b"nonce");
        let c = auth_signed_bytes(b"token", b"nonce2");
        assert_ne!(a, b);
        assert_ne!(a, c);
        // Determinism.
        assert_eq!(a, auth_signed_bytes(b"token", b"nonce"));
    }

    #[test]
    fn chunk_op_signed_bytes_is_deterministic_for_get() {
        let op = ChunkOp::Get {
            address: ChunkAddress([1u8; 32]),
        };
        let cid = crate::types::ClusterId([7u8; 32]);
        let uid = UserId([3u8; 16]);
        let a = chunk_op_signed_bytes(FormatVersion::V1, 7, &cid, &uid, &op, 12345).unwrap();
        let b = chunk_op_signed_bytes(FormatVersion::V1, 7, &cid, &uid, &op, 12345).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn chunk_op_signed_bytes_changes_with_user_or_cluster() {
        let op = ChunkOp::Get {
            address: ChunkAddress([1u8; 32]),
        };
        let cid = crate::types::ClusterId([7u8; 32]);
        let uid = UserId([3u8; 16]);
        let base = chunk_op_signed_bytes(FormatVersion::V1, 7, &cid, &uid, &op, 1).unwrap();
        let other_cid = crate::types::ClusterId([8u8; 32]);
        let other_uid = UserId([4u8; 16]);
        assert_ne!(
            base,
            chunk_op_signed_bytes(FormatVersion::V1, 7, &other_cid, &uid, &op, 1).unwrap()
        );
        assert_ne!(
            base,
            chunk_op_signed_bytes(FormatVersion::V1, 7, &cid, &other_uid, &op, 1).unwrap()
        );
    }

    #[test]
    fn chunk_op_request_round_trips_cbor() {
        let kp = ml_dsa_65_keypair().unwrap();
        let op = ChunkOp::Get {
            address: ChunkAddress([1u8; 32]),
        };
        let cid = crate::types::ClusterId([7u8; 32]);
        let uid = UserId([3u8; 16]);
        let bytes = chunk_op_signed_bytes(FormatVersion::V1, 7, &cid, &uid, &op, 1).unwrap();
        let sig = crate::crypto::pq::ml_dsa_65_sign(&kp.secret, &bytes).unwrap();
        let req = ChunkOpRequest {
            format_version: FormatVersion::V1,
            request_id: 7,
            cluster_id: cid,
            user_id: uid,
            op,
            created_at_ms: 1,
            sig_user: sig,
        };
        let cbor = crate::encoding::cbor_to_vec(&req).unwrap();
        let back: ChunkOpRequest = crate::encoding::cbor_from_slice(&cbor).unwrap();
        assert_eq!(back.request_id, req.request_id);
        assert_eq!(back.created_at_ms, req.created_at_ms);
        assert_eq!(back.cluster_id, cid);
        assert_eq!(back.user_id, uid);
    }

    #[test]
    fn chunk_op_put_round_trips_cbor() {
        let op = ChunkOp::Put {
            addresses: vec![ChunkAddress([1u8; 32]), ChunkAddress([2u8; 32])],
            chunks: vec![vec![0xaa, 0xbb], vec![0xcc]],
        };
        let bytes = crate::encoding::cbor_to_vec(&op).unwrap();
        let back: ChunkOp = crate::encoding::cbor_from_slice(&bytes).unwrap();
        match back {
            ChunkOp::Put { addresses, chunks } => {
                assert_eq!(addresses.len(), 2);
                assert_eq!(chunks, vec![vec![0xaa, 0xbb], vec![0xcc]]);
            }
            _ => panic!("expected Put"),
        }
    }
}
