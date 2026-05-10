//! `vitonomi-vault start` — connect to the hub via WS, run the
//! handshake, send signed heartbeats every 30 s, reconnect on
//! drop with exponential backoff.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use futures::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::Message;

use vitonomi_core::crypto::pq::ml_dsa_65_sign;
use vitonomi_core::protocol::wire::vault_bus::{
    BusFrame, ChainAdvertiseFrame, ChallengeResponseFrame, HeartbeatFrame, HEARTBEAT_INTERVAL_SECS,
};

use crate::accept::load_enrollment;
use crate::chain_store::ChainStore;
use crate::config::VaultConfig;
use crate::hub_client;
use crate::identity;

/// Cadence at which the vault sends signed `Heartbeat` frames. The
/// hub considers the vault offline after `idle_timeout_secs()` of
/// silence (currently 2× this); see `vitonomi_core::protocol::wire::vault_bus`.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(HEARTBEAT_INTERVAL_SECS);

pub async fn run(cfg: VaultConfig) -> anyhow::Result<()> {
    if cfg.hub.url.is_empty() {
        return Err(anyhow!(
            "vault.toml has no hub.url — run `init` then `accept`"
        ));
    }
    if cfg.hub.cert_fingerprint.is_empty() {
        return Err(anyhow!(
            "vault.toml has no hub.cert_fingerprint — run `accept` first"
        ));
    }
    let id = identity::load_or_generate(&cfg.paths.data_dir)?;
    let mut enrollment = load_enrollment(&cfg.paths.data_dir)
        .context("load enrollment.json (have you run `accept` yet?)")?;

    // Best-effort auto-bootstrap. Re-creates the cluster + vault
    // record on a hub that has lost its state (typical after an
    // InMemoryHub reboot). Idempotent: a no-op if already registered.
    // Failure here is non-fatal — we still try the WS handshake; if
    // the hub is intact, it'll succeed.
    if let Err(e) = crate::bootstrap::bootstrap_with(&cfg, &id, &mut enrollment).await {
        tracing::warn!(error = %e, "auto-bootstrap skipped");
    }

    let store = Arc::new(ChainStore::open(&cfg.paths.data_dir)?);

    let mut backoff = hub_client::RECONNECT_BACKOFF_MIN;
    loop {
        let connect = run_session(
            &cfg.hub.url,
            &cfg.hub.cert_fingerprint,
            &id,
            &enrollment,
            store.clone(),
        )
        .await;
        match connect {
            Ok(()) => {
                tracing::info!("vault-bus session ended cleanly");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(error = %e, backoff_ms = backoff.as_millis() as u64,
                    "vault-bus session error; backing off");
                tokio::time::sleep(backoff).await;
                backoff = hub_client::next_backoff(backoff);
            }
        }
    }
}

async fn run_session(
    hub_url: &str,
    fingerprint: &str,
    id: &identity::VaultIdentity,
    enrollment: &crate::accept::Enrollment,
    store: Arc<ChainStore>,
) -> anyhow::Result<()> {
    let ws_url = ws_url_from_https(hub_url)? + "/v1/vault-bus";
    let mut req = ws_url.into_client_request().context("build ws request")?;
    req.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "vitonomi.vault-bus.v1".parse().unwrap(),
    );

    let connector =
        tokio_tungstenite::Connector::Rustls(Arc::new(rustls_client_config(fingerprint)?));
    let (mut socket, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector))
            .await
            .context("ws connect")?;

    // 1. Recv Challenge.
    let frame = recv_frame(&mut socket).await?;
    let chal = match frame {
        BusFrame::Challenge(c) => c.challenge,
        other => return Err(anyhow!("expected Challenge, got {:?}", kind(&other))),
    };

    // 2. Send ChallengeResponse signed with the vault sk.
    let sig = vitonomi_core::crypto::challenge::sign_challenge(&id.secret, &chal)
        .map_err(|e| anyhow!("sign challenge: {e}"))?;
    send_frame(
        &mut socket,
        &BusFrame::ChallengeResponse(ChallengeResponseFrame {
            vault_id: enrollment.vault_id,
            signature: sig,
        }),
    )
    .await?;

    // 3. Recv SessionEstablished.
    let frame = recv_frame(&mut socket).await?;
    let session = match frame {
        BusFrame::SessionEstablished(s) => s,
        BusFrame::Error(e) => return Err(anyhow!("hub rejected: {} — {}", e.code, e.message)),
        other => {
            return Err(anyhow!(
                "expected SessionEstablished, got {:?}",
                kind(&other)
            ))
        }
    };
    tracing::info!(session_id = %session.session_id, "vault session established");

    // Reconcile chain head with the hub. The hub's head is
    // advisory; if it disagrees with our local copy we log + fetch.
    let local_head_seq = store.read_all()?.last().map(|e| e.seq).unwrap_or(0);
    if session.chain_head.seq > local_head_seq {
        tracing::info!(
            hub_seq = session.chain_head.seq,
            local_seq = local_head_seq,
            "hub advertises a higher seq; will fetch via REST in a follow-up"
        );
    } else if session.chain_head.seq < local_head_seq {
        tracing::warn!(
            hub_seq = session.chain_head.seq,
            local_seq = local_head_seq,
            "hub advertises LOWER seq than local — possible suppression; vault is authoritative"
        );
    }

    // 4. Heartbeat loop: send a signed Heartbeat every 30s; drop on
    //    receive of any Disconnect or Error.
    let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .unwrap_or(0);
                let mut signed = Vec::new();
                signed.extend_from_slice(&enrollment.vault_id.0);
                signed.extend_from_slice(&now_ms.to_be_bytes());
                let sig = ml_dsa_65_sign(&id.secret, &signed)
                    .map_err(|e| anyhow!("sign heartbeat: {e}"))?;
                send_frame(&mut socket, &BusFrame::Heartbeat(HeartbeatFrame {
                    vault_id: enrollment.vault_id,
                    ts_ms: now_ms,
                    signature: sig,
                })).await?;

                let (highest_seq, head_hash) = store.head_advertise()?;
                send_frame(&mut socket, &BusFrame::ChainAdvertise(ChainAdvertiseFrame {
                    cluster_id: enrollment.cluster_id,
                    highest_seq,
                    head_hash: head_hash.to_vec(),
                })).await?;
            }
            msg = socket.next() => {
                match msg {
                    None => return Err(anyhow!("ws closed by peer")),
                    Some(Err(e)) => return Err(anyhow!("ws recv: {e}")),
                    Some(Ok(Message::Binary(b))) => {
                        let frame = hub_client::decode_frame(&b)?;
                        match frame {
                            BusFrame::ChainAppend(_) => {
                                tracing::info!("hub broadcast a ChainAppend (handler stub)");
                            }
                            BusFrame::Disconnect(d) => {
                                tracing::info!(reason = %d.reason, "hub disconnect");
                                return Ok(());
                            }
                            BusFrame::Error(e) => {
                                return Err(anyhow!("hub error: {} — {}", e.code, e.message));
                            }
                            BusFrame::ChainAdvertise(_) => {}
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Close(_))) => return Ok(()),
                    Some(Ok(_)) => {}
                }
            }
        }
    }
}

async fn send_frame(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    frame: &BusFrame,
) -> anyhow::Result<()> {
    let bytes = hub_client::encode_frame(frame)?;
    socket
        .send(Message::Binary(bytes.into()))
        .await
        .context("ws send")?;
    Ok(())
}

async fn recv_frame(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> anyhow::Result<BusFrame> {
    loop {
        let msg = socket
            .next()
            .await
            .ok_or_else(|| anyhow!("ws closed before frame"))?
            .context("ws recv")?;
        match msg {
            Message::Binary(b) => return hub_client::decode_frame(&b),
            Message::Close(_) => return Err(anyhow!("peer closed")),
            _ => {}
        }
    }
}

fn rustls_client_config(fingerprint: &str) -> anyhow::Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let verifier = SpkiPin::new(fingerprint)?;
    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

#[derive(Debug)]
struct SpkiPin {
    expected: [u8; 32],
}

impl SpkiPin {
    fn new(fingerprint: &str) -> anyhow::Result<Self> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let b64 = fingerprint
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("fingerprint must start with `sha256:`"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(b64.as_bytes())
            .map_err(|e| anyhow!("decode fingerprint: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!("expected 32-byte SHA-256, got {}", bytes.len()));
        }
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&bytes);
        Ok(Self { expected })
    }
}

impl rustls::client::danger::ServerCertVerifier for SpkiPin {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::Digest as _;
        let spki = extract_spki(end_entity.as_ref())
            .ok_or_else(|| rustls::Error::General("could not extract SPKI".into()))?;
        let mut h = sha2::Sha256::new();
        h.update(spki);
        let actual = h.finalize();
        if actual.as_slice() == self.expected.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("SPKI fingerprint mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn extract_spki(cert_der: &[u8]) -> Option<&[u8]> {
    crate::hub_client::extract_spki_pub(cert_der)
}

fn ws_url_from_https(s: &str) -> anyhow::Result<String> {
    let s = s.trim_end_matches('/');
    if let Some(rest) = s.strip_prefix("https://") {
        Ok(format!("wss://{rest}"))
    } else if let Some(rest) = s.strip_prefix("http://") {
        Ok(format!("ws://{rest}"))
    } else {
        Err(anyhow!("hub.url must start with http:// or https://"))
    }
}

fn kind(f: &BusFrame) -> &'static str {
    match f {
        BusFrame::Challenge(_) => "Challenge",
        BusFrame::ChallengeResponse(_) => "ChallengeResponse",
        BusFrame::SessionEstablished(_) => "SessionEstablished",
        BusFrame::Heartbeat(_) => "Heartbeat",
        BusFrame::ChainAppend(_) => "ChainAppend",
        BusFrame::ChainAdvertise(_) => "ChainAdvertise",
        BusFrame::Error(_) => "Error",
        BusFrame::Disconnect(_) => "Disconnect",
    }
}
