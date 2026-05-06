//! `vitonomi-vault status` — print enrollment + chain-head summary.

use crate::config::VaultConfig;

pub fn run(cfg: VaultConfig) -> anyhow::Result<()> {
    let enrollment = crate::accept::load_enrollment(&cfg.paths.data_dir);
    match enrollment {
        Ok(e) => {
            println!("enrolled: yes");
            println!("  cluster_id:    {}", hex_lower(e.cluster_id.as_bytes()));
            println!("  vault_id:      {}", hex_lower(&e.vault_id.0));
            println!("  enrolled_at_ms: {}", e.enrolled_at_ms);
        }
        Err(_) => {
            println!("enrolled: no — run `vitonomi-vault accept --invite <token>`");
        }
    }
    let store = crate::chain_store::ChainStore::open(&cfg.paths.data_dir)?;
    let chain = store.read_all()?;
    println!("local chain entries: {}", chain.len());
    if let Some(last) = chain.last() {
        println!("  head.seq:    {}", last.seq);
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
