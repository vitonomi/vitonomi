//! Admin chain — append-only, signed, hash-linked log of cluster
//! admin actions. Replicated to the hub *and* to every vault in the
//! cluster, so the cluster identity survives hub failover.
//!
//! Each entry:
//! ```text
//! AdminChainEntry {
//!     format_version: u8,
//!     cluster_id:     [u8; 32],
//!     prev_hash:      [u8; 32],     // sha256 of previous entry bytes
//!     seq:            u64,          // 0 for genesis
//!     action:         AdminAction,
//!     payload:        Vec<u8>,      // CBOR, action-specific
//!     sig:            MlDsa65Signature,  // signs (this entry minus sig)
//! }
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::pq::{
    ml_dsa_65_sign, ml_dsa_65_verify, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
};
use crate::encoding::cbor_to_vec;
use crate::errors::CryptoError;
use crate::types::{ClusterId, FormatVersion};

/// Closed enum of admin actions. New variants get a `u8`
/// discriminator added to the on-wire mapping below; readers reject
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminChainEntry {
    pub format_version: u8,
    pub cluster_id: ClusterId,
    #[serde(with = "serde_bytes")]
    pub prev_hash: Vec<u8>,
    pub seq: u64,
    pub action: AdminAction,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    pub sig: MlDsa65Signature,
}

/// Body without the signature. Used both for sign + verify (the input
/// to `ml_dsa_65_sign`) and for hashing the entry into the next
/// entry's `prev_hash`.
#[derive(Serialize)]
struct EntryBody<'a> {
    format_version: u8,
    cluster_id: &'a ClusterId,
    #[serde(with = "serde_bytes")]
    prev_hash: &'a [u8],
    seq: u64,
    action: AdminAction,
    #[serde(with = "serde_bytes")]
    payload: &'a [u8],
}

/// Sign a fresh entry, given the previous-entry hash (or zero32 for
/// the genesis `cluster-init` entry).
///
/// # Errors
///
/// Returns `CryptoError::Signature` on signing failure or
/// `CryptoError::AdminChain` on body serialisation failure.
pub fn sign_entry(
    admin_sk: &MlDsa65SecretKey,
    cluster_id: ClusterId,
    prev_hash: [u8; 32],
    seq: u64,
    action: AdminAction,
    payload: Vec<u8>,
) -> Result<AdminChainEntry, CryptoError> {
    let body = EntryBody {
        format_version: FormatVersion::V1.as_u8(),
        cluster_id: &cluster_id,
        prev_hash: &prev_hash,
        seq,
        action,
        payload: &payload,
    };
    let body_bytes =
        cbor_to_vec(&body).map_err(|e| CryptoError::AdminChain(format!("body CBOR: {e}")))?;
    let sig = ml_dsa_65_sign(admin_sk, &body_bytes)?;
    Ok(AdminChainEntry {
        format_version: FormatVersion::V1.as_u8(),
        cluster_id,
        prev_hash: prev_hash.to_vec(),
        seq,
        action,
        payload,
        sig,
    })
}

/// Verify a single entry's signature.
///
/// # Errors
///
/// Returns `CryptoError::SignatureInvalid` on bad signature or
/// `CryptoError::AdminChain` on encoding mismatch.
pub fn verify_entry(
    admin_pk: &MlDsa65PublicKey,
    entry: &AdminChainEntry,
) -> Result<(), CryptoError> {
    if entry.format_version != FormatVersion::V1.as_u8() {
        return Err(CryptoError::AdminChain(format!(
            "unsupported format_version {got}",
            got = entry.format_version
        )));
    }
    if entry.prev_hash.len() != 32 {
        return Err(CryptoError::AdminChain("prev_hash must be 32 bytes".into()));
    }
    let body = EntryBody {
        format_version: entry.format_version,
        cluster_id: &entry.cluster_id,
        prev_hash: &entry.prev_hash,
        seq: entry.seq,
        action: entry.action,
        payload: &entry.payload,
    };
    let body_bytes =
        cbor_to_vec(&body).map_err(|e| CryptoError::AdminChain(format!("body CBOR: {e}")))?;
    ml_dsa_65_verify(admin_pk, &entry.sig, &body_bytes)
}

/// Compute the hash of an entry. `prev_hash` of entry `n+1` must
/// equal `entry_hash(entry_n)`.
///
/// # Errors
///
/// Returns `CryptoError::AdminChain` if CBOR encoding fails.
pub fn entry_hash(entry: &AdminChainEntry) -> Result<[u8; 32], CryptoError> {
    let bytes = cbor_to_vec(entry).map_err(|e| CryptoError::AdminChain(format!("CBOR: {e}")))?;
    let digest = Sha256::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Verify a complete chain: every entry's signature, monotonic seq
/// (starting at 0), and hash-link continuity.
///
/// # Errors
///
/// Returns `CryptoError::AdminChain` on any structural break or
/// `CryptoError::SignatureInvalid` on a bad signature.
pub fn verify_chain(
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
        if i == 0 && entry.action != AdminAction::ClusterInit {
            return Err(CryptoError::AdminChain(
                "genesis must be cluster-init".into(),
            ));
        }
        verify_entry(admin_pk, entry)?;
        expected_prev = entry_hash(entry)?;
    }
    Ok(())
}

/// 32 bytes of zeros — the canonical `prev_hash` for the genesis
/// `cluster-init` entry.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cluster::cluster_id_of;
    use crate::crypto::pq::ml_dsa_65_keypair;

    fn build_genesis_chain() -> (MlDsa65PublicKey, ClusterId, Vec<AdminChainEntry>) {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);
        let genesis = sign_entry(
            &kp.secret,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::ClusterInit,
            b"genesis-payload".to_vec(),
        )
        .unwrap();
        (kp.public, cid, vec![genesis])
    }

    #[test]
    fn single_entry_chain_verifies() {
        let (pk, cid, chain) = build_genesis_chain();
        verify_chain(&pk, cid, &chain).unwrap();
    }

    #[test]
    fn multi_entry_chain_verifies() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);

        let e0 = sign_entry(
            &kp.secret,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::ClusterInit,
            vec![1],
        )
        .unwrap();
        let e0_hash = entry_hash(&e0).unwrap();
        let e1 = sign_entry(
            &kp.secret,
            cid,
            e0_hash,
            1,
            AdminAction::VaultEnroll,
            vec![2],
        )
        .unwrap();
        let e1_hash = entry_hash(&e1).unwrap();
        let e2 = sign_entry(
            &kp.secret,
            cid,
            e1_hash,
            2,
            AdminAction::VaultEnroll,
            vec![3],
        )
        .unwrap();

        verify_chain(&kp.public, cid, &[e0, e1, e2]).unwrap();
    }

    #[test]
    fn tampered_signature_rejected() {
        let (pk, cid, mut chain) = build_genesis_chain();
        chain[0].sig.0[0] ^= 0x01;
        assert!(verify_chain(&pk, cid, &chain).is_err());
    }

    #[test]
    fn wrong_admin_pubkey_rejected() {
        let (_pk, cid, chain) = build_genesis_chain();
        let other = ml_dsa_65_keypair().unwrap().public;
        assert!(verify_chain(&other, cid, &chain).is_err());
    }

    #[test]
    fn seq_gap_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);
        let e0 = sign_entry(
            &kp.secret,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::ClusterInit,
            vec![1],
        )
        .unwrap();
        let e0_hash = entry_hash(&e0).unwrap();
        // seq=2 instead of seq=1 — gap.
        let e_gap = sign_entry(
            &kp.secret,
            cid,
            e0_hash,
            2,
            AdminAction::VaultEnroll,
            vec![2],
        )
        .unwrap();
        assert!(verify_chain(&kp.public, cid, &[e0, e_gap]).is_err());
    }

    #[test]
    fn hash_link_break_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);
        let e0 = sign_entry(
            &kp.secret,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::ClusterInit,
            vec![1],
        )
        .unwrap();
        // Wrong prev_hash on entry 1.
        let bogus_prev = [0xaa; 32];
        let e1 = sign_entry(
            &kp.secret,
            cid,
            bogus_prev,
            1,
            AdminAction::VaultEnroll,
            vec![2],
        )
        .unwrap();
        assert!(verify_chain(&kp.public, cid, &[e0, e1]).is_err());
    }

    #[test]
    fn non_genesis_first_entry_rejected() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = cluster_id_of(&kp.public, FormatVersion::V1);
        let bad = sign_entry(
            &kp.secret,
            cid,
            GENESIS_PREV_HASH,
            0,
            AdminAction::VaultEnroll,
            vec![],
        )
        .unwrap();
        assert!(verify_chain(&kp.public, cid, &[bad]).is_err());
    }

    #[test]
    fn cluster_id_mismatch_rejected() {
        let (pk, _cid_real, chain) = build_genesis_chain();
        let other_kp = ml_dsa_65_keypair().unwrap();
        let other_cid = cluster_id_of(&other_kp.public, FormatVersion::V1);
        assert!(verify_chain(&pk, other_cid, &chain).is_err());
    }
}
