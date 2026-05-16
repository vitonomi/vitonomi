//! `vitonomi-mx` ML-DSA-65 keypair persistence.
//!
//! Generated lazily on first `vitonomi-mx start`; persisted as a
//! 32-byte FIPS 204 seed at `<data_dir>/identity.bin` (mode
//! 0600). The pubkey is registered with the hub via
//! `POST /v1/admin/mx-relays`; every signed mx-relay push uses the
//! secret to sign the deterministic CBOR of the push fields.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::pq::{
    ml_dsa_65_keypair, ml_dsa_65_signing_pubkey_from_seed, MlDsa65PublicKey, MlDsa65SecretKey,
};

use crate::state_dir;

/// The mx-relay's identity material in memory.
pub struct MxRelayIdentity {
    pub secret: MlDsa65SecretKey,
    pub public: MlDsa65PublicKey,
}

/// Load existing identity or generate a fresh one.
///
/// # Errors
///
/// File-system / crypto / perm violations.
pub fn load_or_generate(data_dir: &Path) -> anyhow::Result<MxRelayIdentity> {
    state_dir::ensure_data_dir(data_dir)?;
    let path = state_dir::identity_path(data_dir);
    if path.exists() {
        state_dir::enforce_file_perms_0600(&path)?;
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "{} must be 32 bytes (ML-DSA-65 seed); got {}",
                path.display(),
                bytes.len()
            ));
        }
        let secret = MlDsa65SecretKey(bytes);
        let public = ml_dsa_65_signing_pubkey_from_seed(&secret)
            .map_err(|e| anyhow!("derive public key from persisted seed: {e}"))?;
        Ok(MxRelayIdentity { secret, public })
    } else {
        let kp = ml_dsa_65_keypair().map_err(|e| anyhow!("generate keypair: {e}"))?;
        state_dir::write_secure(&path, &kp.secret.0)?;
        Ok(MxRelayIdentity {
            secret: kp.secret,
            public: kp.public,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_generate_creates_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let id1 = load_or_generate(tmp.path()).unwrap();
        let id2 = load_or_generate(tmp.path()).unwrap();
        // Loaded twice → same persisted seed → same pubkey.
        assert_eq!(id1.public.0, id2.public.0);
    }

    #[test]
    fn load_or_generate_fresh_data_dirs_yield_distinct_keys() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let id_a = load_or_generate(a.path()).unwrap();
        let id_b = load_or_generate(b.path()).unwrap();
        assert_ne!(id_a.public.0, id_b.public.0);
    }
}
