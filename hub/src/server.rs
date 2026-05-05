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
        .route("/v1/status", get(crate::routes::status::get_status))
        .route("/v1/clusters", post(crate::routes::clusters::post_register))
        .route(
            "/v1/clusters/restore",
            post(crate::routes::clusters::post_restore),
        )
        .route(
            "/v1/auth/login/start",
            post(crate::routes::auth::post_login_start),
        )
        .route(
            "/v1/auth/login/finish",
            post(crate::routes::auth::post_login_finish),
        )
        .route("/v1/auth/logout", post(crate::routes::auth::post_logout))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
}

/// Bind a listener and serve until shutdown.
///
/// # Errors
///
/// Surfaces listener-bind, IO, and runtime errors.
pub async fn run(cfg: HubConfig) -> anyhow::Result<()> {
    let addr = SocketAddr::new(
        IpAddr::from_str(&cfg.server.bind_addr).context("bad bind_addr")?,
        cfg.server.port,
    );
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    tracing::info!(%addr, "vitonomi-hub listening");
    run_with_listener(listener, AppState::in_memory()).await
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
