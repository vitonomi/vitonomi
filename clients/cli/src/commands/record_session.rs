//! Shared bootstrap path for all `record` subcommands.
//!
//! Each `record put / get / list / delete` invocation needs:
//! 1. `CliState` loaded (cluster_id, user_id, session_token).
//! 2. The user's `MasterSecretKeys` recovered from the encrypted key
//!    blob via a password prompt — gives us `identity_sk` and the
//!    per-user AEAD master.
//! 3. The target vault's libp2p multiaddr discovered via the hub's
//!    `GET /v1/vaults` endpoint.
//! 4. A libp2p Swarm dialled at that multiaddr → `ChunkTransport`.
//! 5. A `LocalHeadStore` for head pointers.
//! 6. A `RecordStore` stitching the above together.
//!
//! Returns both the assembled `RecordStore` and the libp2p client
//! handle so the caller can shut it down cleanly.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context as _};
use libp2p::Multiaddr;

use vitonomi_core::crypto::keyblob::decrypt_with_password;
use vitonomi_core::crypto::keys::MasterSecretKeys;
use vitonomi_core::crypto::pq::MlDsa65SecretKey;
use vitonomi_core::record::record_store::{RecordStore, UserKeys};
use vitonomi_core::record::user_keys::UserAeadMaster;

use crate::commands::local_head_store::LocalHeadStore;
use crate::config::CliConfig;
use crate::hub_client;
use crate::p2p::{dial_vault, load_or_generate_libp2p_key, Libp2pChunkTransport, P2pClientHandle};
use crate::prompts::Prompts;
use crate::state;

/// Everything the caller needs to drive a record op.
pub struct RecordSession {
    pub record_store: RecordStore<Libp2pChunkTransport, LocalHeadStore>,
    pub client_handle: Arc<P2pClientHandle>,
}

impl RecordSession {
    /// Shut down the libp2p client task before exit.
    pub async fn shutdown(self) {
        // Drop the RecordStore first so its references to the handle
        // are released, then unwrap and shut down the client.
        drop(self.record_store);
        if let Ok(handle) = Arc::try_unwrap(self.client_handle) {
            handle.shutdown().await;
        }
    }
}

/// Build a `RecordSession`. Prompts for password, dials the vault,
/// returns the wired store. Use [`open_with_secrets`] if the caller
/// already has unsealed `MasterSecretKeys` and wants to avoid a
/// second password prompt within one CLI invocation.
///
/// # Errors
///
/// Crypto / network / state failures.
pub async fn open<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    state_path: &Path,
    prompts: &mut P,
) -> anyhow::Result<RecordSession> {
    let st = state::load(state_path)?;
    let _ = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let password = prompts.password("Password", false)?;
    let secrets = decrypt_with_password(password.as_bytes(), &st.encrypted_key_blob)
        .map_err(|e| anyhow!("decrypt key blob (wrong password?): {e}"))?;
    open_with_secrets(cfg, state_path, &secrets).await
}

/// Build a `RecordSession` from already-unsealed master secrets.
///
/// Use this when one CLI command needs `identity_sk` (or other
/// `MasterSecretKeys` fields) for client-side signing AND also needs
/// a `RecordSession` to read/write the snapshot chain. Calling
/// [`open`] in that case would prompt for the password twice;
/// `open_with_secrets` reuses the already-unsealed material.
///
/// # Errors
///
/// Crypto / network / state failures.
pub async fn open_with_secrets(
    cfg: &CliConfig,
    state_path: &Path,
    secrets: &MasterSecretKeys,
) -> anyhow::Result<RecordSession> {
    let st = state::load(state_path)?;
    let session_token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let identity_sk = MlDsa65SecretKey(secrets.identity.0.clone());
    let identity_pk = vitonomi_core::crypto::pq::ml_dsa_65_signing_pubkey_from_seed(&identity_sk)
        .map_err(|e| anyhow!("derive identity pubkey from sk: {e}"))?;
    let user_aead_master = UserAeadMaster::from_bytes(secrets.user_aead_master.0.clone())
        .map_err(|e| anyhow!("user_aead_master: {e}"))?;

    // Build a hub HTTP client and look up the vault directory. We
    // pick the first vault whose `multiaddrs` is non-empty.
    // TODO: swap to SPKI-pinned client once the CLI grows a
    // `pinned_client(fingerprint)` helper alongside `default_client`.
    let client = hub_client::default_client()?;
    let vaults = hub_client::list_vaults(&client, &cfg.hub.url, &session_token.0)
        .await
        .context("list vaults")?;
    let vault_addr = vaults
        .vaults
        .into_iter()
        .filter_map(|v| v.multiaddrs.into_iter().next())
        .next()
        .ok_or_else(|| {
            anyhow!(
                "no vault has advertised a libp2p multiaddr yet — \
                 make sure `vitonomi-vault start` is running"
            )
        })?;
    let multiaddr: Multiaddr = vault_addr
        .parse()
        .with_context(|| format!("parse vault multiaddr `{vault_addr}`"))?;

    let state_dir = state_dir_of(state_path);
    let cli_kp = load_or_generate_libp2p_key(&state_dir)?;
    let client_handle = Arc::new(dial_vault(cli_kp, multiaddr).await?);

    let chunk_transport = Libp2pChunkTransport::new(
        client_handle.clone(),
        st.cluster_id,
        st.user_id,
        MlDsa65SecretKey(identity_sk.0.clone()),
    );
    let head_store = LocalHeadStore::new(&state_dir)?;

    let user_keys = UserKeys {
        user_id: st.user_id,
        cluster_id: st.cluster_id,
        identity_pk,
        identity_sk,
        user_aead_master,
    };
    let record_store = RecordStore::new(user_keys, chunk_transport, head_store);

    Ok(RecordSession {
        record_store,
        client_handle,
    })
}

/// The directory that holds the CLI state.json — same dir is where
/// we keep the libp2p key and the local heads/ folder.
fn state_dir_of(state_path: &Path) -> PathBuf {
    state_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}
