//! SMTP server bind + serve loop.
//!
//! Wraps `mailin_embedded::Server` with our [`MxHandler`] and a
//! TLS configuration that uses the wildcard cert from
//! [`crate::tls::resolve`]. STARTTLS is offered on every
//! session.
//!
//! The server runs on a blocking thread (mailin-embedded's
//! `serve` is sync); the tokio runtime stays alive in the
//! background to handle the async dispatch in `data_end`.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{anyhow, Context as _};

use mailin_embedded::{Server, SslConfig};

use crate::smtp::handler::{MxHandler, SharedState};

/// Build + run the SMTP server on `bind_addr`. Blocks the
/// calling thread for the lifetime of the server. Returns
/// when the bind drops or `mailin_embedded::Server::serve`
/// errors.
///
/// `cert_path` and `key_path` point at the (already-resolved)
/// wildcard cert + key. The handler's shared state is the
/// orchestration entry point for every session.
///
/// # Errors
///
/// Bind / TLS / mailin-embedded errors.
pub fn serve(
    bind_addr: SocketAddr,
    base_domain: &str,
    cert_path: &Path,
    key_path: &Path,
    shared: SharedState,
) -> anyhow::Result<()> {
    let handler = MxHandler::new(shared);
    let mut server = Server::new(handler);
    server
        .with_name(base_domain)
        .with_ssl(SslConfig::Trusted {
            cert_path: cert_path.display().to_string(),
            key_path: key_path.display().to_string(),
            chain_path: cert_path.display().to_string(),
        })
        .map_err(|e| anyhow!("mailin-embedded SSL config: {e}"))?
        .with_addr(bind_addr.to_string())
        .map_err(|e| anyhow!("mailin-embedded bind: {e}"))?;
    server
        .serve()
        .map_err(|e| anyhow!("mailin-embedded serve: {e}"))
        .context("smtp server")
}
