//! `vitonomi-cli logout` — revoke session on the hub + delete local
//! `state.json` + wipe the unsealed-secrets cache.

use std::path::Path;

use crate::config::CliConfig;
use crate::hub_client;
use crate::secret_cache;
use crate::state;

/// Run logout.
///
/// # Errors
///
/// Network or persistence failures.
pub async fn run(cfg: &CliConfig, state_path: &Path) -> anyhow::Result<()> {
    let st = match state::load(state_path) {
        Ok(s) => s,
        Err(_) => {
            // No state to delete; nothing to do.
            let _ = clear_local_cache(state_path);
            return Ok(());
        }
    };
    if let Some(token) = st.session_token.as_ref() {
        let client = hub_client::default_client()?;
        let _ = hub_client::logout(&client, &cfg.hub.url, &token.0).await;
    }
    state::delete(state_path)?;
    let _ = clear_local_cache(state_path);
    Ok(())
}

fn clear_local_cache(state_path: &Path) -> anyhow::Result<()> {
    let state_dir = state_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    secret_cache::clear(&state_dir)
}
