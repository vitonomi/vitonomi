//! `vitonomi-mx start` — assemble the SMTP receiver +
//! signed-push pipeline and serve.
//!
//! Steps at boot:
//! 1. Load / generate the mx-relay's ML-DSA-65 identity from
//!    `<data_dir>/identity.bin`.
//! 2. Resolve the wildcard TLS cert (rcgen-generated in dev,
//!    operator-supplied PEMs in prod).
//! 3. Build the [`HubClient`], [`AliasLookup`], and
//!    [`Metrics`] sinks.
//! 4. Hand the assembled [`SharedState`] to
//!    [`crate::smtp::server::serve`] which blocks the calling
//!    thread for the lifetime of the SMTP listener.

use std::net::ToSocketAddrs as _;

use anyhow::{anyhow, Context as _};

use vitonomi_core::protocol::wire::mx_relay_push::MxRelayId;

use crate::config::MxConfig;
use crate::dispatch::alias_lookup::AliasLookup;
use crate::hub_client::HubClient;
use crate::identity::load_or_generate;
use crate::operability::Metrics;
use crate::smtp::handler::SharedState;
use crate::smtp::server;
use crate::state_dir;
use crate::tls::resolve as resolve_tls;

/// Run the relay until shutdown. Currently blocks the calling
/// thread.
///
/// # Errors
///
/// Any of the bootstrap steps (identity, TLS, hub-client,
/// SMTP serve) can fail.
pub async fn run(cfg: MxConfig) -> anyhow::Result<()> {
    // `reqwest`'s `rustls-tls` feature pulls in rustls with the
    // `aws-lc-rs` provider, while our own `rustls` dep enables
    // `ring`. With two providers in scope, rustls 0.23+ refuses
    // to auto-pick a process default and panics on first TLS
    // use. Pin `ring` here (idempotent — returns `Err` if already
    // installed, which we deliberately ignore).
    let _ = rustls::crypto::ring::default_provider().install_default();

    state_dir::ensure_data_dir(&cfg.paths.data_dir)?;
    let identity = std::sync::Arc::new(load_or_generate(&cfg.paths.data_dir)?);
    tracing::info!(base_domain = %cfg.server.base_domain, "loaded mx-relay identity");

    let _tls = resolve_tls(
        &cfg.paths.data_dir,
        &cfg.server.base_domain,
        &cfg.tls.cert_pem,
        &cfg.tls.key_pem,
    )
    .context("resolve TLS")?;
    let cert_path = if cfg.tls.cert_pem.is_empty() {
        state_dir::tls_cert_path(&cfg.paths.data_dir)
    } else {
        std::path::PathBuf::from(&cfg.tls.cert_pem)
    };
    let key_path = if cfg.tls.key_pem.is_empty() {
        state_dir::tls_key_path(&cfg.paths.data_dir)
    } else {
        std::path::PathBuf::from(&cfg.tls.key_pem)
    };

    // `MxRelayId` is derived deterministically from the pubkey —
    // the hub computes the same value on registration, so there's
    // nothing to persist locally besides identity.bin itself.
    let mx_relay_id = MxRelayId::from_pubkey(&identity.public);

    let hub = HubClient::new(&cfg.hub.url).context("build hub client")?;
    let alias_lookup = AliasLookup::new(hub.clone());
    let metrics = Metrics::new();

    let shared = SharedState {
        identity,
        mx_relay_id,
        hub_client: hub,
        alias_lookup,
        metrics,
        base_domain: cfg.server.base_domain.clone(),
    };

    let bind = format!("{}:{}", cfg.server.bind_addr, cfg.server.port);
    let addr = bind
        .to_socket_addrs()
        .with_context(|| format!("resolve bind address {bind}"))?
        .next()
        .ok_or_else(|| anyhow!("no socket address resolved for {bind}"))?;
    tracing::info!(addr = %addr, base_domain = %cfg.server.base_domain, "starting SMTP receiver");

    // mailin-embedded's `serve` is sync. Run it on a blocking
    // task so the surrounding tokio runtime stays alive for
    // the async dispatch in `data_end`.
    let serve_fut = tokio::task::spawn_blocking(move || {
        server::serve(addr, &cfg.server.base_domain, &cert_path, &key_path, shared)
    });
    serve_fut.await.context("smtp serve task")?
}
