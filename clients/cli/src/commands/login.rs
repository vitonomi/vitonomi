//! `vitonomi-cli login` — Scheme A login. Pulls the encrypted key
//! blob from the hub via lookup_id, derives encryption key from
//! the user's password, recovers the identity sk, signs the
//! challenge, and persists the new session token.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::challenge::sign_challenge;
use vitonomi_core::crypto::keyblob::decrypt_with_password;
use vitonomi_core::crypto::lookup_id::{compute_lookup_id, LookupIdParams};
use vitonomi_core::protocol::wire::login::{LoginFinishRequest, LoginStartRequest, UserLookupId};
use vitonomi_core::types::Username;

use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state::{self, CliState};

pub struct LoginArgs<'a> {
    pub state_path: &'a Path,
    pub lookup_argon2: LookupIdParams,
}

/// Run the login flow.
///
/// # Errors
///
/// Validation, crypto, network, or persistence failures.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: LoginArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    if cfg.hub.url.is_empty() {
        return Err(anyhow!(
            "cli.toml has no hub.url — run `init --hub <url>` first"
        ));
    }
    let mut existing = state::load(args.state_path)
        .context("load state.json (run `cluster create` first to bootstrap a cluster context)")?;
    if existing.hub_url != cfg.hub.url {
        return Err(anyhow!(
            "state.json hub_url ({}) does not match cli.toml hub.url ({})",
            existing.hub_url,
            cfg.hub.url
        ));
    }

    let username = Username::parse(&existing.username)
        .map_err(|e| anyhow!("invalid username in state.json: {e}"))?;
    let password = prompts
        .password("Password", false)
        .context("prompt password")?;

    let lookup_bytes = compute_lookup_id(
        &username,
        &existing.pepper(),
        &existing.cluster_id,
        args.lookup_argon2,
    )
    .map_err(|e| anyhow!("compute lookup_id: {e}"))?;
    let lookup_id = UserLookupId(lookup_bytes.to_vec());

    let client = hub_client::default_client()?;
    let start = hub_client::login_start(&client, &cfg.hub.url, &LoginStartRequest { lookup_id })
        .await
        .context("POST /v1/auth/login/start")?;

    // Decrypt the freshly fetched blob locally to recover the
    // identity sk.
    let secrets = decrypt_with_password(password.as_bytes(), &start.encrypted_key_blob)
        .map_err(|e| anyhow!("decrypt key blob (wrong password?): {e}"))?;
    let identity_sk = vitonomi_core::crypto::pq::MlDsa65SecretKey(secrets.identity.0.clone());

    let signature = sign_challenge(&identity_sk, &start.challenge)
        .map_err(|e| anyhow!("sign challenge: {e}"))?;
    let finish = hub_client::login_finish(
        &client,
        &cfg.hub.url,
        &LoginFinishRequest {
            challenge_id: start.challenge_id,
            signature,
        },
    )
    .await
    .context("POST /v1/auth/login/finish")?;

    existing.session_token = Some(finish.session_token);
    existing.session_expires_at_ms = finish.session_expires_at_ms;
    existing.encrypted_key_blob = start.encrypted_key_blob;
    state::save(args.state_path, &existing)?;

    eprintln!(
        "logged in: session expires at ms={}",
        existing.session_expires_at_ms
    );
    Ok(())
}

/// Variant that accepts a pre-loaded `CliState` and returns the
/// updated state without re-reading from disk. Used by other
/// subcommands that need a fresh blob (e.g. `vault invite`).
pub async fn relogin<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    state_in: CliState,
    args: &LoginArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<(CliState, MasterSecretsHandle)> {
    let username =
        Username::parse(&state_in.username).map_err(|e| anyhow!("invalid username: {e}"))?;
    let password = prompts
        .password("Password", false)
        .context("prompt password")?;

    let lookup_bytes = compute_lookup_id(
        &username,
        &state_in.pepper(),
        &state_in.cluster_id,
        args.lookup_argon2,
    )
    .map_err(|e| anyhow!("compute lookup_id: {e}"))?;
    let lookup_id = UserLookupId(lookup_bytes.to_vec());

    let client = hub_client::default_client()?;
    let start =
        hub_client::login_start(&client, &cfg.hub.url, &LoginStartRequest { lookup_id }).await?;
    let secrets = decrypt_with_password(password.as_bytes(), &start.encrypted_key_blob)
        .map_err(|e| anyhow!("decrypt key blob: {e}"))?;
    let identity_sk = vitonomi_core::crypto::pq::MlDsa65SecretKey(secrets.identity.0.clone());
    let sig = sign_challenge(&identity_sk, &start.challenge).map_err(|e| anyhow!("sign: {e}"))?;
    let finish = hub_client::login_finish(
        &client,
        &cfg.hub.url,
        &LoginFinishRequest {
            challenge_id: start.challenge_id,
            signature: sig,
        },
    )
    .await?;
    let mut updated = state_in;
    updated.session_token = Some(finish.session_token);
    updated.session_expires_at_ms = finish.session_expires_at_ms;
    updated.encrypted_key_blob = start.encrypted_key_blob;
    Ok((updated, MasterSecretsHandle { secrets }))
}

/// Hand-off type so callers that need both the freshly verified
/// session AND the unsealed master secrets (e.g. `vault invite`,
/// which needs the cluster admin sk) get them in one round-trip.
pub struct MasterSecretsHandle {
    pub secrets: vitonomi_core::crypto::keys::MasterSecretKeys,
}
