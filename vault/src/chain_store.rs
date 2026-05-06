//! Local admin-chain replica. Each entry is persisted as
//! `<data_dir>/admin-chain/<seq>.cbor` (mode 0600). Hub-blindness:
//! the hub's chain copy is advisory; this on-disk store is the
//! vault's authoritative view.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::admin_chain::{
    verify_chain_outer_only, AdminChainEntry, GENESIS_PREV_HASH,
};
use vitonomi_core::crypto::pq::MlDsa65PublicKey;
use vitonomi_core::encoding::{cbor_from_slice, cbor_to_vec};
use vitonomi_core::types::ClusterId;

use crate::state_dir;

pub struct ChainStore {
    dir: std::path::PathBuf,
}

impl ChainStore {
    /// Open (or create) the on-disk chain at `<data_dir>/admin-chain/`.
    ///
    /// # Errors
    ///
    /// File-system errors (incl. perm violations).
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        state_dir::ensure_data_dir(data_dir)?;
        Ok(Self {
            dir: state_dir::admin_chain_dir(data_dir),
        })
    }

    /// Read the persisted chain in seq order.
    ///
    /// # Errors
    ///
    /// File-system or CBOR-decode failures.
    pub fn read_all(&self) -> anyhow::Result<Vec<AdminChainEntry>> {
        if !self.dir.exists() {
            return Ok(vec![]);
        }
        let mut entries: Vec<(u64, AdminChainEntry)> = Vec::new();
        for dirent in std::fs::read_dir(&self.dir)
            .with_context(|| format!("read_dir {}", self.dir.display()))?
        {
            let dirent = dirent.context("dirent")?;
            let path = dirent.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(seq_str) = name.strip_suffix(".cbor") else {
                continue;
            };
            let Ok(seq) = seq_str.parse::<u64>() else {
                continue;
            };
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let entry: AdminChainEntry =
                cbor_from_slice(&bytes).map_err(|e| anyhow!("decode {}: {e}", path.display()))?;
            entries.push((seq, entry));
        }
        entries.sort_by_key(|(seq, _)| *seq);
        Ok(entries.into_iter().map(|(_, e)| e).collect())
    }

    /// Replace the on-disk chain with `entries`. Verifies linkage +
    /// outer signatures against `admin_pubkey` before writing.
    /// Atomic-ish: writes new files first, then removes stale ones.
    ///
    /// # Errors
    ///
    /// Verification or file-system failures.
    pub fn replace_all(
        &self,
        admin_pubkey: &MlDsa65PublicKey,
        cluster_id: ClusterId,
        entries: &[AdminChainEntry],
    ) -> anyhow::Result<()> {
        verify_chain_outer_only(admin_pubkey, cluster_id, entries)
            .map_err(|e| anyhow!("chain failed verification: {e}"))?;
        // Genesis sanity for a fresh store.
        if let Some(first) = entries.first() {
            if first.seq != 0 || first.prev_hash != GENESIS_PREV_HASH {
                return Err(anyhow!("first entry violates genesis invariant"));
            }
        }
        for entry in entries {
            let path = self.dir.join(format!("{:020}.cbor", entry.seq));
            let bytes = cbor_to_vec(entry).map_err(|e| anyhow!("encode entry: {e}"))?;
            state_dir::write_secure(&path, &bytes)?;
        }
        // Remove any seq files past the new tail.
        let new_max = entries.last().map(|e| e.seq).unwrap_or(0);
        for dirent in std::fs::read_dir(&self.dir)
            .with_context(|| format!("read_dir {}", self.dir.display()))?
        {
            let dirent = dirent.context("dirent")?;
            let path = dirent.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(seq_str) = name.strip_suffix(".cbor") else {
                continue;
            };
            if let Ok(seq) = seq_str.parse::<u64>() {
                if seq > new_max && entries.iter().all(|e| e.seq != seq) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }

    /// Append a single entry. Verifies that `entry.prev_hash`
    /// matches the local head's hash and that `entry.seq` is
    /// `head.seq + 1`.
    ///
    /// # Errors
    ///
    /// Linkage / signature / IO failures.
    pub fn append(
        &self,
        admin_pubkey: &MlDsa65PublicKey,
        cluster_id: ClusterId,
        entry: AdminChainEntry,
    ) -> anyhow::Result<()> {
        let mut chain = self.read_all()?;
        chain.push(entry);
        verify_chain_outer_only(admin_pubkey, cluster_id, &chain)
            .map_err(|e| anyhow!("chain failed verification on append: {e}"))?;
        let last = chain.last().expect("we just pushed");
        let path = self.dir.join(format!("{:020}.cbor", last.seq));
        let bytes = cbor_to_vec(last).map_err(|e| anyhow!("encode entry: {e}"))?;
        state_dir::write_secure(&path, &bytes)?;
        Ok(())
    }

    /// Highest seq + sha256 of head (or zeros + 0 if empty).
    ///
    /// # Errors
    ///
    /// IO / CBOR failures.
    pub fn head_advertise(&self) -> anyhow::Result<(u64, [u8; 32])> {
        let chain = self.read_all()?;
        let Some(last) = chain.last() else {
            return Ok((0, [0u8; 32]));
        };
        let h = vitonomi_core::crypto::admin_chain::entry_hash(last)
            .map_err(|e| anyhow!("entry_hash: {e}"))?;
        Ok((last.seq, h))
    }
}
