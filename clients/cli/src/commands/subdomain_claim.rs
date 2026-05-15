//! `vitonomi-cli subdomain claim <name> --domain <base>` — claim a
//! subdomain on a hub-managed base.
//!
//! # Privacy invariant
//!
//! `subdomain != username` is enforced **client-side** via
//! [`Subdomain::parse_against_username`]. On collision the
//! request never leaves the device — the integration test in
//! Slice 9 asserts zero HTTP traffic on collision.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::keyblob::decrypt_with_password;
use vitonomi_core::crypto::pq::{ml_dsa_65_sign, MlDsa65SecretKey};
use vitonomi_core::types::subdomain::{Subdomain, SubdomainClaim};
use vitonomi_core::types::{FormatVersion, Username};

use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state;

pub struct SubdomainClaimArgs<'a> {
    pub state_path: &'a Path,
    pub subdomain: String,
    pub base_domain: String,
}

/// Claim a subdomain. Client-side privacy check rejects collisions
/// with the user's own username before any HTTP call.
///
/// # Errors
///
/// `subdomain.equals_username` on local rejection (no HTTP call
/// made); network / crypto / state errors otherwise.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: SubdomainClaimArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;
    let username = Username::parse(&st.username)
        .map_err(|e| anyhow!("state.json username invalid: {e}"))?;

    // PRIVACY GATE: this is the ONLY enforcement of `subdomain !=
    // username`. The hub does not re-check (per the relaxed-posture
    // design in `docs/threat-model.md`). The integration test in
    // slice 9 asserts that no HTTP request is sent on collision.
    let sub = Subdomain::parse_against_username(&args.subdomain, &username)
        .map_err(|e| anyhow!("subdomain.equals_username: {e}"))?;

    // Re-prompt password and unseal the user identity sk.
    let password = prompts.password("Password", false)?;
    let secrets = decrypt_with_password(password.as_bytes(), &st.encrypted_key_blob)
        .map_err(|e| anyhow!("decrypt key blob (wrong password?): {e}"))?;
    let identity_sk = MlDsa65SecretKey(secrets.identity.0.clone());
    let identity_pk = vitonomi_core::crypto::pq::ml_dsa_65_signing_pubkey_from_seed(&identity_sk)
        .map_err(|e| anyhow!("derive identity pubkey: {e}"))?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);

    let mut claim = SubdomainClaim {
        format_version: FormatVersion::V1,
        subdomain: sub,
        base_domain: args.base_domain.clone(),
        user_identity_pubkey: identity_pk,
        claimed_at_ms: now_ms,
        sig_user: vitonomi_core::crypto::pq::MlDsa65Signature(vec![]),
    };
    let signed_bytes = claim
        .to_signed_bytes()
        .context("compute SubdomainClaim signed bytes")?;
    claim.sig_user = ml_dsa_65_sign(&identity_sk, &signed_bytes).context("sign SubdomainClaim")?;

    let client = hub_client::default_client()?;
    hub_client::claim_subdomain(&client, &cfg.hub.url, &token.0, &claim).await?;

    tracing::info!(
        subdomain = %claim.subdomain,
        base = %args.base_domain,
        "subdomain claimed"
    );
    Ok(())
}
