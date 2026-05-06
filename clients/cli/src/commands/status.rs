//! `vitonomi-cli status` — print current session, cluster, hub.

use std::path::Path;

use crate::config::CliConfig;
use crate::state;

pub fn run(cfg: &CliConfig, state_path: &Path) -> anyhow::Result<()> {
    println!("hub.url:        {}", cfg.hub.url);
    match state::load(state_path) {
        Err(_) => {
            println!("logged in:      no");
            println!("  run `vitonomi-cli cluster create --username <u>` or `login`");
        }
        Ok(s) => {
            println!("logged in:      yes (username={})", s.username);
            println!("  cluster_id:   {}", hex_lower(s.cluster_id.as_bytes()));
            println!("  user_id:      {}", hex_lower(&s.user_id.0));
            println!("  session_exp:  {}", s.session_expires_at_ms);
        }
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
