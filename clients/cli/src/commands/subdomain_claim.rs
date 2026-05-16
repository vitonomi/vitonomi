//! `vitonomi-cli subdomain claim <name> --domain <base>` — claim a
//! subdomain on a hub-managed base.
//!
//! # Privacy invariant
//!
//! `subdomain != username` is enforced **client-side** via
//! [`Subdomain::parse_against_username`]. On collision the
//! request never leaves the device — the
//! `subdomain_claim_e2e::subdomain_claim_rejects_username_collision_with_zero_http_traffic`
//! integration test pins the zero-HTTP-traffic invariant.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::keyblob::decrypt_with_password;
use vitonomi_core::crypto::pq::{ml_dsa_65_sign, MlDsa65SecretKey};
use vitonomi_core::protocol::wire::domains::DomainStatus;
use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::RecordType;
use vitonomi_core::types::domain::DomainMetadata;
use vitonomi_core::types::subdomain::{Subdomain, SubdomainClaim};
use vitonomi_core::types::{FormatVersion, Username};

use crate::commands::library_session;
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
    // design in `docs/threat-model.md`). The
    // `subdomain_claim_e2e::subdomain_claim_rejects_username_collision_with_zero_http_traffic`
    // integration test asserts no HTTP request leaves the device on
    // collision.
    let sub = Subdomain::parse_against_username(&args.subdomain, &username)
        .map_err(|e| anyhow!("subdomain.equals_username: {e}"))?;

    // Unseal master secrets ONCE — used both to sign the claim
    // (identity_sk) and to open the record session for the Domain
    // record write below.
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

    // Persist the local Domain record so `subdomain list` and the
    // `alias create` namespace-ownership check (which reads local
    // Domain records, not the hub) see this claim.
    let full_domain = format!("{}.{}", claim.subdomain.as_str(), args.base_domain);
    let domain_record_id = DomainMetadata::record_id_for(&full_domain);
    let domain_metadata = DomainMetadata {
        format_version: FormatVersion::V1,
        domain: full_domain.clone(),
        is_custom: false,
        status: DomainStatus::Active,
        verified_at_ms: Some(now_ms),
        challenge: None,
        base_domain: Some(args.base_domain.clone()),
        created_at_ms: now_ms,
    };
    // Reuse the master secrets unsealed above — no second prompt.
    let lib = library_session::open_with_secrets(cfg, args.state_path, &secrets).await?;
    let plaintext = RecordPlaintext {
        metadata: domain_metadata
            .to_metadata_bytes()
            .context("encode DomainMetadata")?,
        body: BodyOp::Remove,
    };
    let put_result = lib
        .session
        .record_store
        .put_or_replace(RecordType::Domain, domain_record_id, plaintext)
        .await;
    lib.shutdown().await;
    put_result.map_err(|e| anyhow!("write local Domain record: {e}"))?;

    tracing::info!(
        subdomain = %claim.subdomain,
        base = %args.base_domain,
        domain = %full_domain,
        record_id = %domain_record_id.to_hex(),
        "subdomain claimed"
    );
    Ok(())
}
