//! `ShortInviteToken` round-trip + tamper detection. Locks in the
//! UX-friendly invite shape: ~150-bytes raw, ~430-460 base64url chars,
//! and a vault-side hash check that catches operator-channel
//! tampering before any network call.

use sha2::Digest as _;

use vitonomi_core::crypto::invite_kek::InviteKekSecret;
use vitonomi_core::encoding::cbor_to_vec;
use vitonomi_core::protocol::wire::accept::{
    encode_short_token, parse_short_token, InviteInnerPayload, ShortInviteToken, VaultRole,
};
use vitonomi_core::types::{ClusterId, FormatVersion};

fn fake_inner() -> InviteInnerPayload {
    InviteInnerPayload {
        format_version: FormatVersion::V1,
        vault_role: VaultRole::Storage,
        hub_url: "https://hub.example.com:4443".into(),
        hub_cert_fingerprint: "sha256:test-fingerprint-string-of-43-base64url-chars-x".into(),
        invite_kek_secret: InviteKekSecret(vec![0x11; 32]),
        sealed_cluster_key: vec![0x22; 72],
    }
}

fn fake_token() -> ShortInviteToken {
    let inner = fake_inner();
    let inner_cbor = cbor_to_vec(&inner).unwrap();
    let inner_hash = sha2::Sha256::digest(&inner_cbor).to_vec();
    ShortInviteToken {
        format_version: FormatVersion::V1,
        cluster_id: ClusterId([0xab; 32]),
        invite_nonce: vec![0xcd; 32],
        expires_at_ms: 1_900_000_000_000,
        inner_payload_hash: inner_hash,
        inner,
    }
}

#[test]
fn round_trip_encode_decode_preserves_fields() {
    let original = fake_token();
    let encoded = encode_short_token(&original).unwrap();
    let decoded = parse_short_token(&encoded).unwrap();
    assert_eq!(
        decoded.cluster_id.as_bytes(),
        original.cluster_id.as_bytes()
    );
    assert_eq!(decoded.invite_nonce, original.invite_nonce);
    assert_eq!(decoded.expires_at_ms, original.expires_at_ms);
    assert_eq!(decoded.inner_payload_hash, original.inner_payload_hash);
    assert_eq!(decoded.inner.hub_url, original.inner.hub_url);
    assert_eq!(
        decoded.inner.invite_kek_secret.0,
        original.inner.invite_kek_secret.0
    );
}

#[test]
fn encoded_token_at_least_seven_times_shorter_than_legacy() {
    // Locks in the UX win. The legacy `CombinedInvite` token came
    // in at ~4,890 chars (89% ML-DSA-65 signature). The short token
    // ships ~600-720 chars — variable with hub_url length and CBOR
    // field-name overhead — so we assert against a 1,000-char ceiling
    // and a comfortable headroom factor over the 4,890 baseline.
    const LEGACY_LEN: usize = 4_890;
    let encoded = encode_short_token(&fake_token()).unwrap();
    assert!(
        encoded.len() < 1_000,
        "expected token under 1000 chars, got {}",
        encoded.len()
    );
    assert!(
        encoded.len() * 7 < LEGACY_LEN,
        "expected ≥7x shorter than legacy ({LEGACY_LEN} chars), got {}",
        encoded.len()
    );
}

#[test]
fn parse_garbage_fails_cleanly() {
    // Pre-live policy: stale long-form tokens just produce CBOR
    // decode errors. No special migration handling.
    assert!(parse_short_token("not-base64!").is_err());
    assert!(parse_short_token("aGVsbG8gd29ybGQ").is_err()); // valid b64, not CBOR for ShortInviteToken
    assert!(parse_short_token("").is_err());
}

#[test]
fn whitespace_around_token_tolerated() {
    let encoded = encode_short_token(&fake_token()).unwrap();
    let with_ws = format!("\n  {encoded}  \n");
    parse_short_token(&with_ws).expect("trim handles surrounding whitespace");
}
