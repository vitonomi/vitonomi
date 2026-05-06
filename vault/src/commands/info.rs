//! `vitonomi-vault info` — print key paths + identity pubkey.

use crate::config::VaultConfig;
use crate::identity;

pub fn run(cfg: VaultConfig) -> anyhow::Result<()> {
    let id = identity::load_or_generate(&cfg.paths.data_dir)?;
    println!("data_dir:        {}", cfg.paths.data_dir.display());
    println!(
        "identity_path:   {}",
        crate::state_dir::identity_path(&cfg.paths.data_dir).display()
    );
    println!(
        "vault_pubkey_b64: {}",
        vitonomi_core::encoding::b64url_encode(id.public.as_bytes())
    );
    println!("hub.url:         {}", cfg.hub.url);
    println!("hub.cert_fp:     {}", cfg.hub.cert_fingerprint);
    Ok(())
}
