//! libp2p data-plane: client side.
//!
//! Builds a libp2p Swarm with the same stack as the vault
//! (TCP + Noise + yamux + cbor request-response on
//! `/vitonomi/chunks/1.0.0`). Implements
//! [`vitonomi_core::record::record_store::ChunkTransport`] so a
//! `RecordStore` can drive snapshots and head pointers through real
//! networking.
//!
//! Each CLI invocation builds a fresh Swarm, dials the vault on its
//! advertised multiaddr, fires the request, awaits the response, then
//! drops the Swarm. No keep-alive yet — sessions are cheap because we
//! re-use the same TCP connection for a sequence of chunk ops within a
//! single CLI command.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context as _};
use async_trait::async_trait;
use futures::stream::StreamExt as _;
use libp2p::request_response::{
    cbor, Config as RrConfig, Event as RrEvent, Message, OutboundRequestId, ProtocolSupport,
};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};
use tokio::sync::{mpsc, oneshot};

use vitonomi_core::crypto::pq::{ml_dsa_65_sign, MlDsa65SecretKey};
use vitonomi_core::errors::CoreError;
use vitonomi_core::protocol::autonomi_bridge::ChunkAddress;
use vitonomi_core::protocol::wire::data_plane::{
    chunk_op_signed_bytes, ChunkOp, ChunkOpRequest, ChunkOpResponse, CHUNKS_PROTOCOL,
};
use vitonomi_core::record::record_store::ChunkTransport;
use vitonomi_core::types::{ClusterId, FormatVersion, UserId};

/// On-disk filename for the CLI's persistent libp2p ed25519 transport
/// key. Not security-critical (regenerating it just changes the peer
/// id; sessions are fresh anyway), but persistent so logs are
/// stable.
const LIBP2P_KEY_FILENAME: &str = "libp2p_identity.ed25519";

/// Load (or generate) the CLI's libp2p ed25519 keypair under
/// `<state_dir>/libp2p_identity.ed25519` (0600).
///
/// # Errors
///
/// Filesystem / encoding errors.
pub fn load_or_generate_libp2p_key(state_dir: &Path) -> anyhow::Result<identity::Keypair> {
    fs::create_dir_all(state_dir)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;
    let path = libp2p_key_path(state_dir);
    if path.exists() {
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        identity::Keypair::from_protobuf_encoding(&bytes).context("decode libp2p ed25519")
    } else {
        let kp = identity::Keypair::generate_ed25519();
        let bytes = kp.to_protobuf_encoding().context("encode libp2p ed25519")?;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        f.write_all(&bytes)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(kp)
    }
}

fn libp2p_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LIBP2P_KEY_FILENAME)
}

#[derive(NetworkBehaviour)]
struct ClientBehaviour {
    chunks: cbor::Behaviour<ChunkOpRequest, ChunkOpResponse>,
}

impl ClientBehaviour {
    fn new() -> Self {
        let protocol = StreamProtocol::new(CHUNKS_PROTOCOL);
        Self {
            chunks: cbor::Behaviour::new(
                [(protocol, ProtocolSupport::Full)],
                RrConfig::default().with_request_timeout(Duration::from_secs(60)),
            ),
        }
    }
}

enum ClientCommand {
    Request(
        ChunkOpRequest,
        oneshot::Sender<anyhow::Result<ChunkOpResponse>>,
    ),
}

/// Handle the CLI uses to drive the Swarm task.
pub struct P2pClientHandle {
    sender: mpsc::Sender<ClientCommand>,
    shutdown: mpsc::Sender<()>,
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl P2pClientHandle {
    /// Send a request and wait for the response.
    pub async fn request(&self, req: ChunkOpRequest) -> anyhow::Result<ChunkOpResponse> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ClientCommand::Request(req, tx))
            .await
            .map_err(|_| anyhow!("p2p client task dropped"))?;
        rx.await.map_err(|_| anyhow!("response channel closed"))?
    }

    /// Stop the background Swarm task. Idempotent.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(()).await;
        let _ = self.join.await;
    }
}

/// Dial a vault multiaddr and spawn a Swarm task. `vault_peer_id` is
/// extracted from the trailing `/p2p/<peer>` component of the
/// multiaddr; missing peer id is an error.
///
/// # Errors
///
/// libp2p build / dial errors.
pub async fn dial_vault(
    transport_keypair: identity::Keypair,
    vault_multiaddr: Multiaddr,
) -> anyhow::Result<P2pClientHandle> {
    let vault_peer_id = vault_multiaddr
        .iter()
        .find_map(|p| match p {
            libp2p::multiaddr::Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .ok_or_else(|| anyhow!("vault multiaddr is missing /p2p/<peer-id> suffix"))?;

    let mut swarm: Swarm<ClientBehaviour> = SwarmBuilder::with_existing_identity(transport_keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| anyhow!("tcp transport: {e:?}"))?
        .with_behaviour(|_| ClientBehaviour::new())
        .map_err(|e| anyhow!("behaviour: {e:?}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    swarm
        .dial(vault_multiaddr.clone())
        .with_context(|| format!("dial {vault_multiaddr}"))?;

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ClientCommand>(8);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    let join = tokio::spawn(async move {
        let mut pending: HashMap<
            OutboundRequestId,
            oneshot::Sender<anyhow::Result<ChunkOpResponse>>,
        > = HashMap::new();
        let mut connected = false;
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    return Ok::<_, anyhow::Error>(());
                }
                cmd = cmd_rx.recv() => {
                    match cmd {
                        None => return Ok(()),
                        Some(ClientCommand::Request(req, reply)) => {
                            // Wait until the vault connection is up before
                            // firing requests. With request-response we
                            // can actually queue them, but explicit-wait
                            // surfaces dial failures fast.
                            if !connected {
                                if let Err(e) =
                                    wait_for_connection(&mut swarm, vault_peer_id).await
                                {
                                    let _ = reply.send(Err(e));
                                    continue;
                                }
                                connected = true;
                            }
                            let id = swarm.behaviour_mut().chunks.send_request(&vault_peer_id, req);
                            pending.insert(id, reply);
                        }
                    }
                }
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == vault_peer_id =>
                        {
                            connected = true;
                        }
                        SwarmEvent::OutgoingConnectionError { error, peer_id, .. } => {
                            tracing::warn!(?peer_id, ?error, "dial failed");
                            // Fail every pending request.
                            for (_, reply) in pending.drain() {
                                let _ = reply.send(Err(anyhow!("dial failed: {error}")));
                            }
                            return Err(anyhow!("dial failed: {error}"));
                        }
                        SwarmEvent::Behaviour(ClientBehaviourEvent::Chunks(rr_event)) => match rr_event {
                            RrEvent::Message {
                                message: Message::Response { request_id, response },
                                ..
                            } => {
                                if let Some(reply) = pending.remove(&request_id) {
                                    let _ = reply.send(Ok(response));
                                }
                            }
                            RrEvent::OutboundFailure { request_id, error, .. } => {
                                if let Some(reply) = pending.remove(&request_id) {
                                    let _ = reply.send(Err(anyhow!("outbound failure: {error}")));
                                }
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(P2pClientHandle {
        sender: cmd_tx,
        shutdown: shutdown_tx,
        join,
    })
}

async fn wait_for_connection(
    swarm: &mut Swarm<ClientBehaviour>,
    target: PeerId,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                return Err(anyhow!("timed out waiting for connection to vault"));
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target => return Ok(()),
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    return Err(anyhow!("dial failed (peer {:?}): {error}", peer_id));
                }
                _ => {}
            },
        }
    }
}

/// `ChunkTransport` impl that talks to a single vault over libp2p.
/// Wraps a [`P2pClientHandle`] and a per-user signing context.
pub struct Libp2pChunkTransport {
    handle: Arc<P2pClientHandle>,
    cluster_id: ClusterId,
    user_id: UserId,
    identity_sk: Arc<MlDsa65SecretKey>,
    counter: AtomicU64,
}

impl Libp2pChunkTransport {
    pub fn new(
        handle: Arc<P2pClientHandle>,
        cluster_id: ClusterId,
        user_id: UserId,
        identity_sk: MlDsa65SecretKey,
    ) -> Self {
        Self {
            handle,
            cluster_id,
            user_id,
            identity_sk: Arc::new(identity_sk),
            counter: AtomicU64::new(1),
        }
    }

    fn next_request_id(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn build_request(&self, op: ChunkOp) -> anyhow::Result<ChunkOpRequest> {
        let request_id = self.next_request_id();
        let ts = Self::now_ms();
        let signed = chunk_op_signed_bytes(
            FormatVersion::V1,
            request_id,
            &self.cluster_id,
            &self.user_id,
            &op,
            ts,
        )
        .map_err(|e| anyhow!("signed-bytes: {e}"))?;
        let sig = ml_dsa_65_sign(&self.identity_sk, &signed).map_err(|e| anyhow!("sign: {e}"))?;
        Ok(ChunkOpRequest {
            format_version: FormatVersion::V1,
            request_id,
            cluster_id: self.cluster_id,
            user_id: self.user_id,
            op,
            created_at_ms: ts,
            sig_user: sig,
        })
    }
}

#[async_trait]
impl ChunkTransport for Libp2pChunkTransport {
    async fn put_chunks(
        &self,
        chunks: &[vitonomi_core::crypto::selfencrypt::Chunk],
    ) -> Result<(), CoreError> {
        let op = ChunkOp::Put {
            addresses: chunks.iter().map(|c| c.address.clone()).collect(),
            chunks: chunks.iter().map(|c| c.bytes.clone()).collect(),
        };
        let req = self.build_request(op).map_err(|e| {
            CoreError::Network(vitonomi_core::errors::NetworkError::Connect(e.to_string()))
        })?;
        let resp = self.handle.request(req).await.map_err(|e| {
            CoreError::Network(vitonomi_core::errors::NetworkError::Connect(e.to_string()))
        })?;
        match resp {
            ChunkOpResponse::PutAck { errors, .. } => {
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(CoreError::Storage(
                        vitonomi_core::errors::StorageError::Backend(format!(
                            "vault rejected {} chunks: first error = {}",
                            errors.len(),
                            errors[0].1
                        )),
                    ))
                }
            }
            ChunkOpResponse::Error { code, message, .. } => Err(map_vault_error(code, message)),
            other => Err(CoreError::Network(
                vitonomi_core::errors::NetworkError::Connect(format!(
                    "unexpected response: {other:?}"
                )),
            )),
        }
    }

    async fn get_chunk(&self, address: &ChunkAddress) -> Result<Vec<u8>, CoreError> {
        let req = self
            .build_request(ChunkOp::Get {
                address: address.clone(),
            })
            .map_err(|e| {
                CoreError::Network(vitonomi_core::errors::NetworkError::Connect(e.to_string()))
            })?;
        let resp = self.handle.request(req).await.map_err(|e| {
            CoreError::Network(vitonomi_core::errors::NetworkError::Connect(e.to_string()))
        })?;
        match resp {
            ChunkOpResponse::GetReply { bytes, found, .. } => {
                if found {
                    Ok(bytes)
                } else {
                    Err(CoreError::Storage(
                        vitonomi_core::errors::StorageError::NotFound,
                    ))
                }
            }
            ChunkOpResponse::Error { code, message, .. } => Err(map_vault_error(code, message)),
            other => Err(CoreError::Network(
                vitonomi_core::errors::NetworkError::Connect(format!(
                    "unexpected response: {other:?}"
                )),
            )),
        }
    }
}

fn map_vault_error(code: u16, message: String) -> CoreError {
    match code {
        401 => CoreError::Auth(vitonomi_core::errors::AuthError::Forbidden),
        400 => CoreError::Validation(vitonomi_core::errors::ValidationError::Other(message)),
        _ => CoreError::Network(vitonomi_core::errors::NetworkError::Http {
            status: code,
            message,
        }),
    }
}
