//! `vitonomi-cli mx register --pubkey <hex> --namespace <ns>...` —
//! admin-only. POSTs the mx-relay's ML-DSA-65 pubkey + allowed
//! namespaces to the hub's `/v1/admin/mx-relays`. The hub responds
//! `204 No Content`; the `MxRelayId` is derived deterministically from
//! the pubkey on both sides, so nothing needs to be pasted back to
//! the relay box. After this call, `vitonomi-mx start` works.
//!
//! Auth: uses the persisted session token if still valid; otherwise
//! prompts for the admin password and re-runs the Scheme A login
//! transparently via [`crate::commands::login::relogin`].

use std::path::Path;

use anyhow::{anyhow, Context as _};

use vitonomi_core::crypto::lookup_id::LookupIdParams;
use vitonomi_core::crypto::pq::MlDsa65PublicKey;
use vitonomi_core::encoding::{hex_decode, hex_encode};
use vitonomi_core::protocol::wire::mx_relay_push::{MxRelayId, RegisterMxRelayRequest};

use crate::commands::login::{self, LoginArgs};
use crate::config::CliConfig;
use crate::hub_client;
use crate::prompts::Prompts;
use crate::state;

pub struct MxRegisterArgs<'a> {
    pub state_path: &'a Path,
    pub pubkey_hex: String,
    pub namespaces: Vec<String>,
    pub lookup_argon2: LookupIdParams,
}

/// Run.
///
/// # Errors
///
/// Malformed pubkey hex, network failures, or hub rejection (e.g.
/// non-admin bearer, unknown namespace policy).
#[allow(clippy::print_stdout)]
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: MxRegisterArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    if args.namespaces.is_empty() {
        return Err(anyhow!("at least one --namespace required"));
    }
    let pubkey_bytes =
        hex_decode(&args.pubkey_hex).map_err(|e| anyhow!("--pubkey hex decode: {e}"))?;
    if pubkey_bytes.is_empty() {
        return Err(anyhow!("--pubkey is empty"));
    }
    let mx_relay_pubkey = MlDsa65PublicKey(pubkey_bytes);

    // Resolve a fresh bearer — refresh via password prompt if missing
    // or expired. `relogin` returns the updated `CliState` and leaves
    // the save to the caller (mirrors how `login` composes both halves).
    let st = state::load(args.state_path)?;
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(u64::MAX);
    let bearer = if st.session_token.is_some() && st.session_expires_at_ms > now_ms {
        st.session_token
            .as_ref()
            .map(|t| t.0.clone())
            .ok_or_else(|| anyhow!("unreachable"))?
    } else {
        let (updated, _secrets) = login::relogin(
            cfg,
            st,
            &LoginArgs {
                state_path: args.state_path,
                lookup_argon2: args.lookup_argon2,
            },
            prompts,
        )
        .await
        .context("re-login for admin session")?;
        state::save(args.state_path, &updated)?;
        updated
            .session_token
            .as_ref()
            .map(|t| t.0.clone())
            .ok_or_else(|| anyhow!("relogin returned no session token"))?
    };

    let client = hub_client::default_client()?;
    hub_client::register_mx_relay(
        &client,
        &cfg.hub.url,
        &bearer,
        &RegisterMxRelayRequest {
            mx_relay_pubkey: mx_relay_pubkey.clone(),
            allowed_namespaces: args.namespaces.clone(),
        },
    )
    .await
    .context("POST /v1/admin/mx-relays")?;

    // Compute the derived `MxRelayId` locally for the confirmation
    // message. The mx relay's `start` derives the identical value from
    // its own identity.bin — nothing needs to be pasted back.
    let mx_relay_id_hex = hex_encode(&MxRelayId::from_pubkey(&mx_relay_pubkey).0);
    tracing::info!(
        mx_relay_id = %mx_relay_id_hex,
        namespaces = ?args.namespaces,
        "registered mx relay"
    );
    eprintln!(
        "registered mx relay (mx_relay_id={mx_relay_id_hex}, namespaces={:?})",
        args.namespaces
    );
    eprintln!("mx relay can now run `vitonomi-mx start`");
    Ok(())
}
