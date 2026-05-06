//! `vitonomi-cli cluster restore` — restore an existing cluster on
//! a fresh hub from a locally exported chain. Re-derives keys from
//! the BIP-39 seed phrase + password, posts a chain export to the
//! new hub, persists the new state.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::admin_chain::AdminChainEntry;
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keyblob::decrypt_with_password;
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::encoding::cbor_from_slice;
use vitonomi_core::protocol::hub_control_plane::ClusterRestoreRequest;
use vitonomi_core::protocol::wire::admin_chain::ChainExport;
use vitonomi_core::protocol::wire::login::UserLookupId;
use vitonomi_core::types::{FormatVersion, Username};

use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state::{self, CliState};

pub struct ClusterRestoreArgs<'a> {
    pub state_path: &'a Path,
    pub username: String,
    pub chain_export_path: &'a Path,
    pub lookup_argon2: LookupIdParams,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: ClusterRestoreArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    if cfg.hub.url.is_empty() {
        return Err(anyhow!(
            "cli.toml has no hub.url — run `init --hub <url>` first"
        ));
    }

    // Read the chain export from the supplied path.
    let chain_bytes = std::fs::read(args.chain_export_path)
        .with_context(|| format!("read {}", args.chain_export_path.display()))?;
    let chain: Vec<AdminChainEntry> =
        cbor_from_slice(&chain_bytes).map_err(|e| anyhow!("decode chain export: {e}"))?;

    // We pull the encrypted key blob from the existing state file
    // (this is the simplest mini-MVP path; a future iteration adds
    // a `--blob-file` flag for cross-device restore from the
    // seed-phrase backup file).
    let prior = state::load(args.state_path)
        .context("load state.json (mini-MVP restore reuses the local blob)")?;
    let username = Username::parse(&args.username).map_err(|e| anyhow!("invalid username: {e}"))?;
    let password = prompts.password("Password", false)?;
    let secrets = decrypt_with_password(password.as_bytes(), &prior.encrypted_key_blob)
        .map_err(|e| anyhow!("decrypt key blob (wrong password?): {e}"))?;

    // Re-derive cluster_id from the cluster_admin pubkey (which we
    // recover from the stored pubkey on the prior state — same
    // cluster).
    let cluster_id = prior.cluster_id;
    let admin_pk_recovered = vitonomi_core::crypto::pq::ml_dsa_65_signing_pubkey_from_seed(
        &vitonomi_core::crypto::pq::MlDsa65SecretKey(secrets.cluster_admin.0.clone()),
    )
    .map_err(|e| anyhow!("derive admin pubkey from secret: {e}"))?;
    if cluster_id != cluster_id_of(&admin_pk_recovered, FormatVersion::V1) {
        return Err(anyhow!(
            "recovered admin pubkey does not match cluster_id in state.json"
        ));
    }

    let pepper_bytes = secrets.cluster_pepper.0.clone();
    let pepper = vitonomi_core::crypto::cluster_keys::ClusterPepper(pepper_bytes.clone());
    let lookup_bytes = compute_lookup_id(&username, &pepper, &cluster_id, args.lookup_argon2)
        .map_err(|e| anyhow!("compute lookup_id: {e}"))?;
    let lookup_id = UserLookupId(lookup_bytes.to_vec());

    let identity_pk = vitonomi_core::crypto::pq::ml_dsa_65_signing_pubkey_from_seed(
        &vitonomi_core::crypto::pq::MlDsa65SecretKey(secrets.identity.0.clone()),
    )
    .map_err(|e| anyhow!("derive identity pubkey: {e}"))?;
    let kem_pk = prior.cluster_admin_pubkey.clone(); // placeholder, see comment below
    let _ = kem_pk;
    let master_pubkeys = vitonomi_core::crypto::keys::MasterPublicKeys {
        identity: identity_pk,
        cluster_admin: admin_pk_recovered.clone(),
        // KEM pubkey is similarly re-derivable from the secret; for
        // the mini-MVP we punt and use a deterministic re-derivation
        // helper that lands when ml-kem stabilises seeded keygen.
        // Until then, we re-use whatever the hub has on file via
        // re-registration; the restore path here is sufficient for
        // single-device flows.
        kem: vitonomi_core::crypto::pq::MlKem768PublicKey(vec![]),
    };

    let client = hub_client::default_client()?;
    let resp = hub_client::restore_cluster(
        &client,
        &cfg.hub.url,
        &ClusterRestoreRequest {
            lookup_id: lookup_id.clone(),
            master_pubkeys,
            encrypted_key_blob: prior.encrypted_key_blob.clone(),
            chain_export: ChainExport {
                cluster_id,
                entries: chain,
            },
        },
    )
    .await
    .context("POST /v1/clusters/restore")?;

    let new_state = CliState {
        username: username.as_str().to_string(),
        hub_url: cfg.hub.url.clone(),
        cluster_id: resp.cluster_id,
        cluster_admin_pubkey: admin_pk_recovered,
        cluster_pepper: pepper_bytes,
        user_id: resp.user_id,
        session_token: Some(resp.session_token),
        session_expires_at_ms: resp.session_expires_at_ms,
        encrypted_key_blob: prior.encrypted_key_blob,
    };
    state::save(args.state_path, &new_state)?;
    eprintln!("cluster restored to {}", cfg.hub.url);
    Ok(())
}
