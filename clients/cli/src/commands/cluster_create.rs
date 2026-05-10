//! `vitonomi-cli cluster create --username <u>` — bootstrap a fresh
//! cluster on a hub. Generates seed phrase + master keys + cluster
//! pepper + cluster shared key, derives lookup_id, builds the
//! genesis admin chain entry, encrypts master secrets into a key
//! blob (Argon2id over the password), POSTs `/v1/clusters`,
//! persists session + cluster context to `state.json`.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::admin_chain::{sign_entry, AdminAction, GENESIS_PREV_HASH};
use vitonomi_core::crypto::argon2::Argon2Params;
use vitonomi_core::crypto::cluster::cluster_id_of;
use vitonomi_core::crypto::keyblob::encrypt_with_password;
use vitonomi_core::crypto::keys::{GenesisMaterial, MasterPublicKeys, MasterSecretKeys};
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::protocol::hub_control_plane::ClusterRegisterRequest;
use vitonomi_core::protocol::wire::login::UserLookupId;
use vitonomi_core::types::{FormatVersion, Username};

use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state::{self, CliState};

pub struct ClusterCreateArgs<'a> {
    pub config_path: &'a Path,
    pub state_path: &'a Path,
    pub username: String,
    pub keyblob_argon2: Argon2Params,
    pub lookup_argon2: LookupIdParams,
    pub print_seed_phrase: bool,
}

/// Run the cluster-create flow.
///
/// # Errors
///
/// Validation, network, or persistence failures.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: ClusterCreateArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    if cfg.hub.url.is_empty() {
        return Err(anyhow!(
            "cli.toml has no hub.url — run `vitonomi-cli init --hub <url>` first"
        ));
    }
    let username = Username::parse(&args.username).map_err(|e| anyhow!("invalid username: {e}"))?;

    // 1. Prompt password (twice).
    let password = prompts
        .password(&format!("Password for {username}"), true)
        .context("prompt password")?;

    // 2. Generate genesis material (seed + master keypairs + pepper + shared_key).
    let genesis = GenesisMaterial::generate().map_err(|e| anyhow!("generate genesis: {e}"))?;
    let pubkeys = MasterPublicKeys::from(&genesis.master_keys);
    let cluster_id = cluster_id_of(&pubkeys.cluster_admin, FormatVersion::V1);

    // 3. Compute lookup_id (Argon2id over username+pepper salted by cluster_id).
    let lookup_bytes = compute_lookup_id(
        &username,
        &genesis.cluster_pepper,
        &cluster_id,
        args.lookup_argon2,
    )
    .map_err(|e| anyhow!("compute lookup_id: {e}"))?;
    let lookup_id = UserLookupId(lookup_bytes.to_vec());

    // 4. Build the genesis admin-chain entry (sealed inner under
    //    cluster_shared_key, outer signed by cluster_admin sk).
    let genesis_entry = sign_entry(
        &genesis.master_keys.cluster_admin.secret,
        &genesis.cluster_shared_key,
        cluster_id,
        GENESIS_PREV_HASH,
        0,
        AdminAction::ClusterInit,
        Vec::new(),
    )
    .map_err(|e| anyhow!("sign genesis entry: {e}"))?;

    // 5. Build the encrypted key blob (Argon2id over password).
    let secrets = MasterSecretKeys::from_genesis(&genesis);
    let encrypted_key_blob =
        encrypt_with_password(password.as_bytes(), args.keyblob_argon2, &secrets)
            .map_err(|e| anyhow!("encrypt key blob: {e}"))?;

    // 6. POST /v1/clusters.
    let client = hub_client::default_client()?;
    let resp = hub_client::register_cluster(
        &client,
        &cfg.hub.url,
        &ClusterRegisterRequest {
            lookup_id,
            master_pubkeys: pubkeys.clone(),
            encrypted_key_blob: encrypted_key_blob.clone(),
            genesis_entry,
        },
    )
    .await
    .context("POST /v1/clusters")?;

    // 7. Persist state (mode 0600).
    let cli_state = CliState {
        username: username.as_str().to_string(),
        hub_url: cfg.hub.url.clone(),
        cluster_id: resp.cluster_id,
        cluster_admin_pubkey: pubkeys.cluster_admin.clone(),
        cluster_pepper: genesis.cluster_pepper.0.clone(),
        user_id: resp.user_id,
        session_token: Some(resp.session_token.clone()),
        session_expires_at_ms: resp.session_expires_at_ms,
        encrypted_key_blob,
    };
    state::save(args.state_path, &cli_state)?;

    // 8. Probe + pin the hub's TLS fingerprint into cli.toml. Skipped
    //    for plain-http hubs (test path) and best-effort for https
    //    (operator can still pass --fingerprint to `vault invite`).
    if cfg.hub.url.starts_with("https://") {
        match hub_client::fetch_hub_fingerprint(&cfg.hub.url).await {
            Ok(fp) => {
                let mut cfg_with_fp = cfg.clone();
                cfg_with_fp.hub.cert_fingerprint = fp.clone();
                if let Err(e) = cfg_with_fp.write_to(args.config_path) {
                    tracing::warn!(
                        error = %e,
                        "could not persist hub.cert_fingerprint to cli.toml; \
                         pass --fingerprint manually to `vault invite`"
                    );
                } else {
                    eprintln!("  hub.cert_fingerprint: {fp}");
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not probe hub TLS fingerprint; \
                     pass --fingerprint manually to `vault invite`"
                );
            }
        }
    }

    // 8. Print seed phrase (operator-visible, write-down-NOW
    //    banner). In tests we suppress via the args flag.
    if args.print_seed_phrase {
        eprintln!();
        eprintln!("======== RECOVERY SEED PHRASE — WRITE THIS DOWN NOW =========");
        eprintln!("{}", genesis.seed_phrase.to_words());
        eprintln!("=============================================================");
        eprintln!("  cluster_id:   {}", hex_lower(resp.cluster_id.as_bytes()));
        eprintln!("  user_id:      {}", hex_lower(&resp.user_id.0));
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
