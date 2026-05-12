//! Rendezvous wire types — hub-issued introduction tokens that let a
//! client dial a vault over libp2p direct.
//!
//! Flow:
//! 1. Client → hub HTTPS: `POST /v1/rendezvous { session_token,
//!    cluster_id, vault_id, client_libp2p_peer_id_bytes }`.
//! 2. Hub validates the session, looks up the vault's published
//!    multiaddrs (advertised over the vault-bus WSS via
//!    [`crate::protocol::wire::vault_bus::AdvertiseAddrsFrame`]),
//!    signs a [`RendezvousToken`] with the hub's ML-DSA-65 signing
//!    key, and returns it alongside the multiaddrs.
//! 3. Client opens a libp2p connection to the vault (trying each
//!    multiaddr in turn), then presents the token + a fresh
//!    user signature over the protocol channel
//!    `/vitonomi/auth/1.0.0`. See
//!    [`crate::protocol::wire::data_plane::AuthFrame`].
//!
//! Hub-blindness: the token is bound to `(cluster_id, user_id,
//! vault_id, client_libp2p_peer_id, issued_at_ms, expires_at_ms)`.
//! The hub is a TTP for introductions only — the user's signing key
//! is needed to actually transact on the data plane, and the
//! vault's identity pubkey is pinned client-side, so a malicious
//! hub cannot synthesise a vault.

use serde::{Deserialize, Serialize};

use crate::crypto::pq::MlDsa65Signature;
use crate::types::{ClusterId, FormatVersion, SessionToken, UserId, VaultId};

/// HTTP request body for `POST /v1/rendezvous`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousRequest {
    pub format_version: FormatVersion,
    pub session_token: SessionToken,
    pub cluster_id: ClusterId,
    pub vault_id: VaultId,
    /// Multihash bytes of the client's libp2p ed25519 transport key.
    /// Bound into the token so a token leaked from one client cannot
    /// be re-played from a different libp2p peer.
    #[serde(with = "serde_bytes")]
    pub client_libp2p_peer_id_bytes: Vec<u8>,
}

/// Body of the hub-signed introduction token. Travels back to the
/// client over HTTPS and is replayed on the libp2p
/// `/vitonomi/auth/1.0.0` stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousToken {
    pub format_version: FormatVersion,
    pub cluster_id: ClusterId,
    pub user_id: UserId,
    pub vault_id: VaultId,
    /// Identical to the `client_libp2p_peer_id_bytes` of the
    /// request that produced this token.
    #[serde(with = "serde_bytes")]
    pub client_libp2p_peer_id_bytes: Vec<u8>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// ML-DSA-65 signature by the hub signing key over the
    /// deterministic CBOR of the fields above (i.e. CBOR(this
    /// struct with `sig_hub` replaced by `MlDsa65Signature(vec![])`)).
    /// The verifier reconstructs the same value with the sig field
    /// zeroed before calling `ml_dsa_65_verify`.
    pub sig_hub: MlDsa65Signature,
}

impl RendezvousToken {
    /// Build the bytes the hub signs / clients verify. Stable layout:
    /// 1 (format_version) + 32 (cluster_id) + 16 (user_id) + 16
    /// (vault_id) + 4 (peer_id length, BE) + peer_id_bytes + 8
    /// (issued_at_ms BE) + 8 (expires_at_ms BE).
    #[must_use]
    pub fn signed_bytes(
        format_version: FormatVersion,
        cluster_id: &ClusterId,
        user_id: &UserId,
        vault_id: &VaultId,
        client_libp2p_peer_id_bytes: &[u8],
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(1 + 32 + 16 + 16 + 4 + client_libp2p_peer_id_bytes.len() + 16);
        buf.push(format_version.as_u8());
        buf.extend_from_slice(&cluster_id.0);
        buf.extend_from_slice(&user_id.0);
        buf.extend_from_slice(&vault_id.0);
        let len_be = (client_libp2p_peer_id_bytes.len() as u32).to_be_bytes();
        buf.extend_from_slice(&len_be);
        buf.extend_from_slice(client_libp2p_peer_id_bytes);
        buf.extend_from_slice(&issued_at_ms.to_be_bytes());
        buf.extend_from_slice(&expires_at_ms.to_be_bytes());
        buf
    }
}

/// HTTP response body for `POST /v1/rendezvous`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RendezvousResponse {
    pub token: RendezvousToken,
    /// libp2p multiaddrs the vault has advertised (most-recent first).
    /// The client dials them in order until one accepts.
    pub vault_multiaddrs: Vec<String>,
}

/// Body of `GET /v1/hub/info` — public info every client needs to
/// pin and verify the hub. The TLS SPKI fingerprint is already in
/// `CliState`; this struct exposes the hub's ML-DSA-65 signing
/// pubkey so clients can verify [`RendezvousToken`] signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubInfo {
    pub format_version: FormatVersion,
    pub hub_signing_pubkey: crate::crypto::pq::MlDsa65PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix() -> (ClusterId, UserId, VaultId) {
        (ClusterId([7u8; 32]), UserId([3u8; 16]), VaultId([4u8; 16]))
    }

    #[test]
    fn signed_bytes_layout_is_stable() {
        let (cid, uid, vid) = fix();
        let a = RendezvousToken::signed_bytes(
            FormatVersion::V1,
            &cid,
            &uid,
            &vid,
            b"peerid-bytes",
            1_000_000,
            2_000_000,
        );
        let b = RendezvousToken::signed_bytes(
            FormatVersion::V1,
            &cid,
            &uid,
            &vid,
            b"peerid-bytes",
            1_000_000,
            2_000_000,
        );
        assert_eq!(a, b, "signed bytes must be deterministic");
    }

    #[test]
    fn signed_bytes_changes_with_every_field() {
        let (cid, uid, vid) = fix();
        let base =
            RendezvousToken::signed_bytes(FormatVersion::V1, &cid, &uid, &vid, b"peerid", 1, 2);
        let cid2 = ClusterId([99u8; 32]);
        let uid2 = UserId([99u8; 16]);
        let vid2 = VaultId([99u8; 16]);
        assert_ne!(
            base,
            RendezvousToken::signed_bytes(FormatVersion::V1, &cid2, &uid, &vid, b"peerid", 1, 2)
        );
        assert_ne!(
            base,
            RendezvousToken::signed_bytes(FormatVersion::V1, &cid, &uid2, &vid, b"peerid", 1, 2)
        );
        assert_ne!(
            base,
            RendezvousToken::signed_bytes(FormatVersion::V1, &cid, &uid, &vid2, b"peerid", 1, 2)
        );
        assert_ne!(
            base,
            RendezvousToken::signed_bytes(FormatVersion::V1, &cid, &uid, &vid, b"other", 1, 2)
        );
        assert_ne!(
            base,
            RendezvousToken::signed_bytes(FormatVersion::V1, &cid, &uid, &vid, b"peerid", 99, 2)
        );
        assert_ne!(
            base,
            RendezvousToken::signed_bytes(FormatVersion::V1, &cid, &uid, &vid, b"peerid", 1, 99)
        );
    }
}
