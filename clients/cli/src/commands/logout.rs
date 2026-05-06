//! `vitonomi-cli logout` — revoke session on the hub + delete
//! local `state.json`.

use std::path::Path;

use crate::config::CliConfig;
use crate::hub_client;
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
            return Ok(());
        }
    };
    if let Some(token) = st.session_token.as_ref() {
        let client = hub_client::default_client()?;
        let _ = hub_client::logout(&client, &cfg.hub.url, &token.0).await;
    }
    state::delete(state_path)?;
    Ok(())
}
