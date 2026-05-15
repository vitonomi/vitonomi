//! axum app + router assembly + listener binding.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr as _;

use anyhow::Context as _;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;

use crate::config::HubConfig;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        // Meta
        .route("/v1/status", get(crate::routes::status::get_status))
        // Cluster register / restore
        .route("/v1/clusters", post(crate::routes::clusters::post_register))
        .route(
            "/v1/clusters/restore",
            post(crate::routes::clusters::post_restore),
        )
        .route(
            "/v1/clusters/bootstrap",
            post(crate::routes::clusters::post_bootstrap),
        )
        // Auth (Scheme A)
        .route(
            "/v1/auth/login/start",
            post(crate::routes::auth::post_login_start),
        )
        .route(
            "/v1/auth/login/finish",
            post(crate::routes::auth::post_login_finish),
        )
        .route("/v1/auth/logout", post(crate::routes::auth::post_logout))
        // Key blob
        .route(
            "/v1/keyblob",
            get(crate::routes::keyblob::get).put(crate::routes::keyblob::put),
        )
        // Vaults
        .route("/v1/vaults", get(crate::routes::vaults::get_list))
        .route(
            "/v1/vaults/invites",
            post(crate::routes::vaults::post_invite),
        )
        .route(
            "/v1/vaults/accept",
            post(crate::routes::vaults::post_accept),
        )
        // Public user identity-pubkey lookup (no auth — pubkeys are
        // public). Vaults call this to verify per-op signatures on
        // /vitonomi/chunks/1.0.0.
        .route(
            "/v1/clusters/{cluster_id}/users/{user_id}/identity-pubkey",
            get(crate::routes::users::get_identity_pubkey),
        )
        // Admin chain
        .route(
            "/v1/admin-chain/{cluster_id}/head",
            get(crate::routes::admin_chain::get_head),
        )
        .route(
            "/v1/admin-chain/{cluster_id}",
            get(crate::routes::admin_chain::get_chain)
                .post(crate::routes::admin_chain::post_append),
        )
        // ── Phase 7: subdomains ───────────────────────────────────
        .route(
            "/v1/subdomains",
            post(crate::routes::phase7::post_claim_subdomain),
        )
        .route(
            "/v1/subdomains/{base}/{sub}",
            get(crate::routes::phase7::get_subdomain)
                .delete(crate::routes::phase7::delete_subdomain),
        )
        .route(
            "/v1/managed-base-domains",
            get(crate::routes::phase7::get_managed_base_domains),
        )
        // ── Phase 7: custom domains ───────────────────────────────
        .route(
            "/v1/domains",
            get(crate::routes::phase7::get_list_custom_domains)
                .post(crate::routes::phase7::post_add_custom_domain),
        )
        .route(
            "/v1/domains/{domain}",
            axum::routing::delete(crate::routes::phase7::delete_custom_domain),
        )
        .route(
            "/v1/domains/{domain}/verify",
            post(crate::routes::phase7::post_verify_custom_domain),
        )
        // ── Phase 7: alias directory ──────────────────────────────
        .route(
            "/v1/aliases/directory",
            post(crate::routes::phase7::post_publish_alias_pubkey),
        )
        .route(
            "/v1/aliases/directory/{handle}/{namespace}",
            get(crate::routes::phase7::get_lookup_alias_pubkey)
                .delete(crate::routes::phase7::delete_alias_pubkey),
        )
        // ── Phase 7: per-alias inbox + relay push ────────────────
        .route(
            "/v1/mx/messages",
            post(crate::routes::phase7::post_relay_push),
        )
        .route(
            "/v1/aliases/{alias_id}/inbox",
            get(crate::routes::phase7::get_alias_inbox),
        )
        .route(
            "/v1/aliases/{alias_id}/inbox/ack",
            post(crate::routes::phase7::post_alias_inbox_ack),
        )
        .route(
            "/v1/admin/relays",
            post(crate::routes::phase7::post_register_relay),
        )
        // WebSocket vault-bus
        .route("/v1/vault-bus", get(crate::ws::vault_bus::ws_upgrade))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_http::request_id::SetRequestIdLayer::x_request_id(
            tower_http::request_id::MakeRequestUuid,
        ))
}

/// Bind a TLS listener and serve until shutdown. Production entrypoint.
///
/// # Errors
///
/// Surfaces TLS-material resolution, listener-bind, and runtime errors.
pub async fn run(cfg: HubConfig) -> anyhow::Result<()> {
    // Install rustls' process-wide CryptoProvider before any TLS work
    // happens. axum-server's `RustlsConfig::from_pem` builds its own
    // ServerConfig internally and assumes a provider is already
    // installed; without this the first incoming handshake panics
    // with "Could not automatically determine the process-level
    // CryptoProvider". Idempotent — safe to call repeatedly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls = crate::tls::resolve(&cfg).context("resolve TLS material")?;
    tracing::info!(spki = %tls.spki_fingerprint, "TLS material loaded");

    let addr = SocketAddr::new(
        IpAddr::from_str(&cfg.server.bind_addr).context("bad bind_addr")?,
        cfg.server.port,
    );
    let policy = cfg.bootstrap.to_policy().context("bootstrap policy")?;
    let app = router(AppState::in_memory_with_policy(policy));
    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_pem(tls.cert_pem.clone(), tls.key_pem.clone())
            .await
            .context("build axum-server rustls config")?;
    tracing::info!(%addr, "vitonomi-hub listening (HTTPS)");
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .context("serve loop")
}

/// Variant that takes a pre-bound listener and explicit state. Used
/// by integration tests that need an ephemeral port + a custom
/// `AppState`.
///
/// # Errors
///
/// Surfaces serve loop errors.
pub async fn run_with_listener(listener: TcpListener, state: AppState) -> anyhow::Result<()> {
    let app = router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve loop")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
