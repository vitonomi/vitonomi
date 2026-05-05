//! Admin chain — append-only, signed, hash-linked log of cluster
//! admin actions. Hub-blind: every entry is a two-layer envelope
//! where the inner action+payload is AEAD-sealed under
//! `cluster_shared_key` and only the outer envelope is hub-readable.
//!
//! See `docs/data-format.md#admin-chain-entry` for the byte layout.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::aead::{open, seal};
use crate::crypto::cluster_keys::ClusterSharedKey;
use crate::crypto::pq::{
    ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
};
use crate::encoding::{cbor_from_slice, cbor_to_vec};
use crate::errors::CryptoError;
use crate::types::{ClusterId, FormatVersion};

/// Closed enum of admin actions. New variants get a `u8`
/// discriminator added to the on-wire mapping; readers reject
/// unknown values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdminAction {
    ClusterInit,
    VaultEnroll,
    VaultRevoke,
    UserInvite,
    UserRevoke,
}

/// Outer envelope — what the hub stores and serves. The hub can
/// verify `sig_admin_outer` against the cluster admin pubkey to
/// gate admission, but cannot read `sealed_inner`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminChainEntry {
    pub format_version: u8,
    pub cluster_id: ClusterId,
    #[serde(with = "serde_bytes")]
    pub prev_hash: Vec<u8>,
    pub seq: u64,
    /// Reserved for admin-key rotation (v1.1+). Currently always 0.
    pub admin_pubkey_epoch: u32,
    /// Reserved for `cluster_shared_key` rotation (v1.1+). Currently 0.
    pub key_epoch: u32,
    /// AEAD ciphertext of CBOR-encoded [`AdminChainEntryInner`]
    /// under `cluster_shared_key`. AAD = `cluster_id || seq_be8 ||
    /// prev_hash`.
    #[serde(with = "serde_bytes")]
    pub sealed_inner: Vec<u8>,
    /// ML-DSA-65 signature over CBOR of the outer envelope fields
    /// above (everything except `sig_admin_outer`).
    pub sig_admin_outer: MlDsa65Signature,
}

/// Inner body — only readable by cluster members holding the
/// cluster shared key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminChainEntryInner {
    pub format_version: u8,
    pub action: AdminAction,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// ML-DSA-65 signature over `action_byte || payload`.
    pub sig_admin_inner: MlDsa65Signature,
}

#[derive(Serialize)]
struct OuterBody<'a> {
    format_version: u8,
    cluster_id: &'a ClusterId,
    #[serde(with = "serde_bytes")]
    prev_hash: &'a [u8],
    seq: u64,
    admin_pubkey_epoch: u32,
    key_epoch: u32,
    #[serde(with = "serde_bytes")]
    sealed_inner: &'a [u8],
}

/// 32 bytes of zeros — the canonical `prev_hash` for the genesis
/// `cluster-init` entry.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// Build a fresh chain entry. Seals the inner body under
/// `cluster_shared_key`, signs the outer envelope with `admin_sk`.
///
/// # Errors
///
/// `CryptoError::Signature`/`AeadSeal`/`AdminChain` on failure.
pub fn sign_entry(
    admin_sk: &MlDsa65SecretKey,
    cluster_shared_key: &ClusterSharedKey,
    cluster_id: ClusterId,
    prev_hash: [u8; 32],
    seq: u64,
    action: AdminAction,
    payload: Vec<u8>,
) -> Result<AdminChainEntry, CryptoError> {
    let format_version = FormatVersion::V1.as_u8();
    let admin_pubkey_epoch: u32 = 0;
    let key_epoch: u32 = 0;

    let inner_signed = inner_signed_bytes(action, &payload);
    let sig_admin_inner = ml_dsa_65_sign(admin_sk, &inner_signed)?;
    let inner = AdminChainEntryInner {
        format_version,
        action,
        payload,
        sig_admin_inner,
    };
    let inner_bytes =
        cbor_to_vec(&inner).map_err(|e| CryptoError::AdminChain(format!("inner CBOR: {e}")))?;

    let aad = aad_bytes(&cluster_id, seq, &prev_hash);
    let aead_key = cluster_shared_key.to_aead_key()?;
    let sealed_inner = seal(&aead_key, &inner_bytes, &aad)?;

    let body = OuterBody {
        format_version,
        cluster_id: &cluster_id,
        prev_hash: &prev_hash,
        seq,
        admin_pubkey_epoch,
        key_epoch,
        sealed_inner: &sealed_inner,
    };
    let body_bytes =
        cbor_to_vec(&body).map_err(|e| CryptoError::AdminChain(format!("outer CBOR: {e}")))?;
    let sig_admin_outer = ml_dsa_65_sign(admin_sk, &body_bytes)?;

    Ok(AdminChainEntry {
        format_version,
        cluster_id,
        prev_hash: prev_hash.to_vec(),
        seq,
        admin_pubkey_epoch,
        key_epoch,
        sealed_inner,
        sig_admin_outer,
    })
}

/// Verify just the outer envelope's admin signature. This is what
/// the **hub** does — it does not need `cluster_shared_key`.
///
/// # Errors
///
/// `CryptoError::SignatureInvalid` on bad signature; `AdminChain`
/// on encoding mismatch.
pub fn verify_outer(
    admin_pk: &MlDsa65PublicKey,
    entry: &AdminChainEntry,
) -> Result<(), CryptoError> {
    if entry.format_version != FormatVersion::V1.as_u8() {
        return Err(CryptoError::AdminChain(format!(
            "unsupported format_version {}",
            entry.format_version
        )));
    }
    if entry.prev_hash.len() != 32 {
        return Err(CryptoError::AdminChain("prev_hash must be 32 bytes".into()));
    }
    let body = OuterBody {
        format_version: entry.format_version,
        cluster_id: &entry.cluster_id,
        prev_hash: &entry.prev_hash,
        seq: entry.seq,
        admin_pubkey_epoch: entry.admin_pubkey_epoch,
        key_epoch: entry.key_epoch,
        sealed_inner: &entry.sealed_inner,
    };
    let body_bytes =
        cbor_to_vec(&body).map_err(|e| CryptoError::AdminChain(format!("outer CBOR: {e}")))?;
    ml_dsa_65_verify(admin_pk, &entry.sig_admin_outer, &body_bytes)
}

/// Open the sealed inner and verify both signatures. Vault/client
/// path — needs `cluster_shared_key`.
pub fn unseal_and_verify_inner(
    admin_pk: &MlDsa65PublicKey,
    cluster_shared_key: &ClusterSharedKey,
    entry: &AdminChainEntry,
) -> Result<AdminChainEntryInner, CryptoError> {
    verify_outer(admin_pk, entry)?;
    let aad = {
        let mut prev = [0u8; 32];
        prev.copy_from_slice(&entry.prev_hash);
        aad_bytes(&entry.cluster_id, entry.seq, &prev)
    };
    let aead_key = cluster_shared_key.to_aead_key()?;
    let inner_bytes = open(&aead_key, &entry.sealed_inner, &aad)?;
    let inner: AdminChainEntryInner = cbor_from_slice(&inner_bytes)
        .map_err(|e| CryptoError::AdminChain(format!("inner CBOR: {e}")))?;
    if inner.format_version != FormatVersion::V1.as_u8() {
        return Err(CryptoError::AdminChain(format!(
            "unsupported inner format_version {}",
            inner.format_version
        )));
    }
    let inner_signed = inner_signed_bytes(inner.action, &inner.payload);
    ml_dsa_65_verify(admin_pk, &inner.sig_admin_inner, &inner_signed)?;
    Ok(inner)
}

/// SHA-256 of the CBOR-encoded outer envelope. `prev_hash` of entry
/// `n+1` MUST equal `entry_hash(entry_n)`.
pub fn entry_hash(entry: &AdminChainEntry) -> Result<[u8; 32], CryptoError> {
    let bytes = cbor_to_vec(entry).map_err(|e| CryptoError::AdminChain(format!("CBOR: {e}")))?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Verify a complete chain (vault-side: requires `cluster_shared_key`).
pub fn verify_chain(
    admin_pk: &MlDsa65PublicKey,
    cluster_shared_key: &ClusterSharedKey,
    cluster_id: ClusterId,
    chain: &[AdminChainEntry],
) -> Result<(), CryptoError> {
    if chain.is_empty() {
        return Err(CryptoError::AdminChain("empty chain".into()));
    }
    let mut expected_prev = [0u8; 32];
    for (i, entry) in chain.iter().enumerate() {
        if entry.cluster_id != cluster_id {
            return Err(CryptoError::AdminChain("cluster_id mismatch".into()));
        }
        if entry.seq != i as u64 {
            return Err(CryptoError::AdminChain(format!(
                "seq gap: expected {i}, got {}",
                entry.seq
            )));
        }
        if entry.prev_hash != expected_prev {
            return Err(CryptoError::AdminChain(format!(
                "hash-link break at seq {}",
                entry.seq
            )));
        }
        let inner = unseal_and_verify_inner(admin_pk, cluster_shared_key, entry)?;
        if i == 0 && inner.action != AdminAction::ClusterInit {
            return Err(CryptoError::AdminChain(
                "genesis must be cluster-init".into(),
            ));
        }
        expected_prev = entry_hash(entry)?;
    }
    Ok(())
}

/// Verify chain *outer signatures + linkage* only — the hub-side
/// fast path (no `cluster_shared_key` needed).
pub fn verify_chain_outer_only(
    admin_pk: &MlDsa65PublicKey,
    cluster_id: ClusterId,
    chain: &[AdminChainEntry],
) -> Result<(), CryptoError> {
    if chain.is_empty() {
        return Err(CryptoError::AdminChain("empty chain".into()));
    }
    let mut expected_prev = [0u8; 32];
    for (i, entry) in chain.iter().enumerate() {
        if entry.cluster_id != cluster_id {
            return Err(CryptoError::AdminChain("cluster_id mismatch".into()));
        }
        if entry.seq != i as u64 {
            return Err(CryptoError::AdminChain(format!(
                "seq gap: expected {i}, got {}",
                entry.seq
            )));
        }
        if entry.prev_hash != expected_prev {
            return Err(CryptoError::AdminChain(format!(
                "hash-link break at seq {}",
                entry.seq
            )));
        }
        verify_outer(admin_pk, entry)?;
        expected_prev = entry_hash(entry)?;
    }
    Ok(())
}

fn aad_bytes(cluster_id: &ClusterId, seq: u64, prev_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 8 + 32);
    aad.extend_from_slice(cluster_id.as_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.extend_from_slice(prev_hash);
    aad
}

fn inner_signed_bytes(action: AdminAction, payload: &[u8]) -> Vec<u8> {
    let action_byte: u8 = match action {
        AdminAction::ClusterInit => 0x01,
        AdminAction::VaultEnroll => 0x02,
        AdminAction::VaultRevoke => 0x03,
        AdminAction::UserInvite => 0x04,
        AdminAction::UserRevoke => 0x05,
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(action_byte);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cluster::cluster_id_of;
    use crate::crypto::pq::ml_dsa_65_keypair;

    fn shared_key() -> ClusterSharedKey {
        ClusterSharedKey(vec![0xab; 32])
    }

    fn build_genesis() -> (
        MlDsa65PublicKey,
        ClusterSharedKey,
        ClusterId,
        Vec<AdminChainEntry>,
    ) {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);
        let csk = shared_key();
        let g = sign_entry(
            &kp.secret,
            &csk,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::ClusterInit,
            b"genesis".to_vec(),
        )
        .unwrap();
        (kp.public, csk, cid, vec![g])
    }

    #[test]
    fn outer_only_verify_works_without_shared_key() {
        let (pk, _csk, cid, chain) = build_genesis();
        verify_chain_outer_only(&pk, cid, &chain).unwrap();
    }

    #[test]
    fn full_verify_unseals_and_validates_inner() {
        let (pk, csk, cid, chain) = build_genesis();
        verify_chain(&pk, &csk, cid, &chain).unwrap();
    }

    #[test]
    fn multi_entry_chain_verifies() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);
        let csk = shared_key();
        let e0 = sign_entry(
            &kp.secret,
            &csk,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::ClusterInit,
            vec![1],
        )
        .unwrap();
        let e0h = entry_hash(&e0).unwrap();
        let e1 = sign_entry(
            &kp.secret,
            &csk,
            cid,
            e0h,
            1,
            AdminAction::VaultEnroll,
            vec![2],
        )
        .unwrap();
        verify_chain(&kp.public, &csk, cid, &[e0, e1]).unwrap();
    }

    #[test]
    fn tampered_outer_signature_rejected() {
        let (pk, _csk, cid, mut chain) = build_genesis();
        chain[0].sig_admin_outer.0[0] ^= 0x01;
        assert!(verify_chain_outer_only(&pk, cid, &chain).is_err());
    }

    #[test]
    fn wrong_shared_key_fails_unseal() {
        let (pk, _csk, cid, chain) = build_genesis();
        let bad = ClusterSharedKey(vec![0u8; 32]);
        assert!(verify_chain(&pk, &bad, cid, &chain).is_err());
    }

    #[test]
    fn seq_gap_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);
        let csk = shared_key();
        let e0 = sign_entry(
            &kp.secret,
            &csk,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::ClusterInit,
            vec![1],
        )
        .unwrap();
        let e0h = entry_hash(&e0).unwrap();
        let e_gap = sign_entry(
            &kp.secret,
            &csk,
            cid,
            e0h,
            2,
            AdminAction::VaultEnroll,
            vec![2],
        )
        .unwrap();
        assert!(verify_chain(&kp.public, &csk, cid, &[e0, e_gap]).is_err());
    }

    #[test]
    fn non_genesis_first_entry_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);
        let csk = shared_key();
        let bad = sign_entry(
            &kp.secret,
            &csk,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::VaultEnroll,
            vec![],
        )
        .unwrap();
        assert!(verify_chain(&kp.public, &csk, cid, &[bad]).is_err());
    }
}
