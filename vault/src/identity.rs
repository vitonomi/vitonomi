//! Vault keypair persistence. ML-DSA-65 secret key (32-byte FIPS
//! 204 seed) stored as `<data_dir>/identity.bin` with mode 0600.
//! Generated lazily on first start; refused to load if the file or
//! its parent directory has wrong perms.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::pq::{
    ml_dsa_65_keypair, ml_dsa_65_signing_pubkey_from_seed, MlDsa65PublicKey, MlDsa65SecretKey,
};

use crate::state_dir;

pub struct VaultIdentity {
    pub secret: MlDsa65SecretKey,
    pub public: MlDsa65PublicKey,
}

/// Load existing identity or generate a fresh one. Always enforces
/// `data_dir` perms (no world-write) and `identity.bin` perms (0600).
///
/// # Errors
///
/// File-system / crypto / perm violations.
pub fn load_or_generate(data_dir: &Path) -> anyhow::Result<VaultIdentity> {
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
        let secret = MlDsa65SecretKey(bytes.clone());
        let public = ml_dsa_65_signing_pubkey_from_seed(&secret)
            .map_err(|e| anyhow!("derive public key from persisted seed: {e}"))?;
        Ok(VaultIdentity { secret, public })
    } else {
        let kp = ml_dsa_65_keypair().map_err(|e| anyhow!("generate keypair: {e}"))?;
        state_dir::write_secure(&path, &kp.secret.0)?;
        Ok(VaultIdentity {
            secret: kp.secret,
            public: kp.public,
        })
    }
}
