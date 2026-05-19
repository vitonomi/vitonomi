//! `vitonomi-cli alias create <full-email>` — create a new alias
//! with its own ML-KEM-768 keypair, publish the directory entry,
//! and write the matching `Alias` record (metadata + body face)
//! to the snapshot chain.
//!
//! # Privacy invariants
//!
//! - Address is parsed via [`AliasMetadata::parse_address`] which
//!   splits on the rightmost `@` (rejects malformed input).
//! - The namespace MUST belong to the user — either a claimed
//!   subdomain or a verified custom domain. We check this against
//!   the local `Domain` records on the snapshot chain (no extra
//!   HTTP round-trip) and refuse with `alias.namespace_not_owned`
//!   on miss.

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::keys::MlKem768SecretKeyBytes;
use vitonomi_core::crypto::pq::{ml_dsa_65_sign, ml_kem_768_keypair, MlDsa65SecretKey};
use vitonomi_core::crypto::random::random_bytes;
use vitonomi_core::protocol::wire::aliases::AliasDirectoryEntry;
use vitonomi_core::record::record_store::{BodyOp, RecordPlaintext};
use vitonomi_core::record::{RecordId, RecordType};
use vitonomi_core::types::alias::{AliasBody, AliasMetadata, SpamPolicy};
use vitonomi_core::types::domain::DomainMetadata;
use vitonomi_core::types::FormatVersion;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::secret_cache;
use crate::state;

pub struct AliasCreateArgs<'a> {
    pub state_path: &'a Path,
    pub address: String,
    pub label: Option<String>,
    pub tags: Vec<String>,
}

/// Run alias create.
///
/// # Errors
///
/// `alias.namespace_not_owned` on namespace check fail; otherwise
/// crypto / network / state / record-store errors.
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: AliasCreateArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let st = state::load(args.state_path)?;
    let token = st
        .session_token
        .as_ref()
        .ok_or_else(|| anyhow!("no active session — run `login` first"))?;

    let (alias_handle, namespace) = AliasMetadata::parse_address(&args.address)
        .map_err(|e| anyhow!("alias.address_invalid: {e}"))?;

    // Unseal master secrets ONCE — used both for the record session
    // below and for signing the AliasDirectoryEntry via identity_sk.
    // The secret_cache helper skips the prompt when the cache is hot.
    let state_dir = state_dir_of(args.state_path);
    let secrets = secret_cache::read_or_prompt(&st, &state_dir, prompts)?;
    let identity_sk = MlDsa65SecretKey(secrets.identity.0.clone());
    let identity_pk = vitonomi_core::crypto::pq::ml_dsa_65_signing_pubkey_from_seed(&identity_sk)
        .map_err(|e| anyhow!("derive identity pubkey: {e}"))?;

    // Open a record session with the already-unsealed secrets so we
    // don't prompt the user a second time.
    let lib = library_session::open_with_secrets(cfg, args.state_path, &secrets).await?;

    // PRIVACY CHECK: namespace MUST be a domain the cluster owns.
    let owned = lib
        .session
        .record_store
        .list_metadata(RecordType::Domain)
        .await
        .map_err(|e| anyhow!("list domains: {e}"))?
        .iter()
        .filter_map(|(_, bytes)| DomainMetadata::from_metadata_bytes(bytes).ok())
        .any(|d| d.domain.eq_ignore_ascii_case(&namespace));
    if !owned {
        lib.shutdown().await;
        return Err(anyhow!(
            "alias.namespace_not_owned: namespace {namespace:?} is not \
             a claimed subdomain or verified custom domain"
        ));
    }

    // Generate a fresh ML-KEM-768 keypair for this alias.
    let kem_kp = ml_kem_768_keypair().context("generate alias KEM keypair")?;
    let alias_kem_secret_bytes = MlKem768SecretKeyBytes(kem_kp.secret.0.clone());

    // Pick a random 16-byte alias_id (also serves as the alias_id_hint
    // and as the RecordId).
    let alias_id_bytes = random_bytes(16).map_err(|e| anyhow!("rng: {e}"))?;
    let mut alias_id_arr = [0u8; 16];
    alias_id_arr.copy_from_slice(&alias_id_bytes);
    let alias_id = RecordId(alias_id_arr);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);

    // 1. Build the directory entry with a placeholder signature,
    //    compute the canonical signed bytes via the wire-type
    //    helper, then overwrite `sig_user` with the real signature.
    //    Hub-side verify recomputes the same bytes.
    let mut dir_entry = AliasDirectoryEntry {
        alias_handle: alias_handle.clone(),
        namespace: namespace.clone(),
        alias_id,
        alias_kem_pubkey: kem_kp.public.clone(),
        user_identity_pubkey: identity_pk,
        sig_user: vitonomi_core::crypto::pq::MlDsa65Signature(vec![]),
    };
    let signed = dir_entry
        .signed_bytes()
        .context("encode AliasDirectoryEntry signed bytes")?;
    let sig_user = ml_dsa_65_sign(&identity_sk, &signed).context("sign alias pubkey")?;
    dir_entry.sig_user = sig_user.clone();
    let client = hub_client::default_client()?;
    hub_client::publish_alias_pubkey(&client, &cfg.hub.url, &token.0, &dir_entry).await?;

    // 2. Build the AliasMetadata + AliasBody and write to the snapshot.
    let metadata = AliasMetadata {
        format_version: FormatVersion::V1,
        alias_id_hint: alias_id_arr,
        alias_handle: alias_handle.clone(),
        namespace: namespace.clone(),
        label: args.label,
        alias_kem_pubkey: kem_kp.public,
        sig_user_over_pubkey: sig_user,
        expiry_ms: None,
        active: true,
        spam_policy: SpamPolicy::OpenInbox,
        tags: args.tags,
        last_used_at_ms: None,
        created_at_ms: now_ms,
    };
    let body = AliasBody {
        format_version: FormatVersion::V1,
        alias_kem_secret_key: alias_kem_secret_bytes,
    };

    let plaintext = RecordPlaintext {
        metadata: metadata
            .to_metadata_bytes()
            .context("encode alias metadata")?,
        body: BodyOp::Set(body.to_body_bytes().context("encode alias body")?),
    };
    lib.session
        .record_store
        .put_or_replace(RecordType::Alias, alias_id, plaintext)
        .await
        .map_err(|e| anyhow!("put alias record: {e}"))?;

    tracing::info!(
        address = %format!("{alias_handle}@{namespace}"),
        alias_id = %alias_id.to_hex(),
        "alias created and published"
    );

    lib.shutdown().await;
    Ok(())
}

fn state_dir_of(state_path: &Path) -> std::path::PathBuf {
    state_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}
