//! libp2p data-plane: vault side.
//!
//! Builds a libp2p Swarm with TCP + Noise + yamux + `request_response`
//! (CBOR codec) speaking the [`vitonomi_core::protocol::wire::data_plane::
//! CHUNKS_PROTOCOL`] protocol. Each inbound request is verified
//! against the user's identity pubkey (cached after first lookup),
//! then dispatched to [`SqliteVaultStorage`].
//!
//! Two cooperating pieces:
//!
//! - [`P2pNode::spawn`] — starts the Swarm in a background task and
//!   returns a [`P2pHandle`] holding the current set of listen
//!   multiaddrs (`watch::Receiver<Vec<Multiaddr>>`).
//! - [`Resolver`] — async closure type the node calls when it sees a
//!   `(cluster_id, user_id)` it hasn't cached. Concretely backed by
//!   an HTTP call to the hub's `/v1/clusters/.../identity-pubkey`
//!   endpoint, but kept abstract so tests can wire an in-memory map.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context as _};
use futures::stream::StreamExt as _;
use libp2p::request_response::{
    cbor, Config as RrConfig, Event as RrEvent, Message, ProtocolSupport,
};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, noise, tcp, yamux, Multiaddr, StreamProtocol, Swarm, SwarmBuilder};
use tokio::sync::{mpsc, watch, Mutex};
use vitonomi_core::crypto::pq::{ml_dsa_65_verify, MlDsa65PublicKey};
use vitonomi_core::encoding::cbor_to_vec;
use vitonomi_core::errors::{CoreError, CryptoError, StorageError};
use vitonomi_core::protocol::vault_storage::VaultStorage;
use vitonomi_core::protocol::wire::data_plane::{
    chunk_op_signed_bytes, ChunkOp, ChunkOpRequest, ChunkOpResponse, CHUNKS_PROTOCOL,
};
use vitonomi_core::types::{ClusterId, UserId};

use crate::state_dir;

/// Filename for the persisted libp2p ed25519 transport key.
const TRANSPORT_KEY_FILE: &str = "libp2p_identity.ed25519";

/// Hub-shaped lookup for user identity pubkeys. Async so the real impl
/// can hit HTTPS; the in-memory test impl returns immediately.
#[async_trait::async_trait]
pub trait IdentityResolver: Send + Sync {
    async fn lookup(
        &self,
        cluster_id: &ClusterId,
        user_id: &UserId,
    ) -> Result<MlDsa65PublicKey, anyhow::Error>;
}

/// Production [`IdentityResolver`] that calls
/// `GET /v1/clusters/{cid}/users/{uid}/identity-pubkey` over the
/// vault's existing SPKI-pinned reqwest client. Pubkeys are public
/// material — no auth required.
pub struct HttpIdentityResolver {
    client: reqwest::Client,
    hub_url: String,
}

impl HttpIdentityResolver {
    #[must_use]
    pub fn new(client: reqwest::Client, hub_url: String) -> Self {
        Self { client, hub_url }
    }
}

#[derive(serde::Deserialize)]
struct UserIdentityPubkeyResponse {
    identity_pubkey: MlDsa65PublicKey,
}

#[async_trait::async_trait]
impl IdentityResolver for HttpIdentityResolver {
    async fn lookup(
        &self,
        cluster_id: &ClusterId,
        user_id: &UserId,
    ) -> Result<MlDsa65PublicKey, anyhow::Error> {
        let cid_hex = vitonomi_core::encoding::hex_encode(&cluster_id.0);
        let uid_hex = vitonomi_core::encoding::hex_encode(&user_id.0);
        let url = format!(
            "{}/v1/clusters/{}/users/{}/identity-pubkey",
            self.hub_url.trim_end_matches('/'),
            cid_hex,
            uid_hex
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .context("identity-pubkey GET")?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("identity-pubkey lookup status {status}");
        }
        let body: UserIdentityPubkeyResponse =
            resp.json().await.context("decode identity-pubkey body")?;
        Ok(body.identity_pubkey)
    }
}

/// Load (or generate) the vault's libp2p ed25519 transport key. Stored
/// at `<data_dir>/libp2p_identity.ed25519` at mode 0600.
///
/// # Errors
///
/// Filesystem / encoding errors.
pub fn load_or_generate_transport_keypair(data_dir: &Path) -> anyhow::Result<identity::Keypair> {
    state_dir::ensure_data_dir(data_dir)?;
    let path = data_dir.join(TRANSPORT_KEY_FILE);
    if path.exists() {
        state_dir::enforce_file_perms_0600(&path)?;
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let kp = identity::Keypair::from_protobuf_encoding(&bytes)
            .context("decode libp2p ed25519 from protobuf")?;
        Ok(kp)
    } else {
        let kp = identity::Keypair::generate_ed25519();
        let bytes = kp
            .to_protobuf_encoding()
            .context("encode libp2p ed25519 to protobuf")?;
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

/// Behaviour wraps libp2p's CBOR request-response on
/// `/vitonomi/chunks/1.0.0`. We don't need `identify` / `ping` for the
/// MVP; identify is useful once libp2p `relay::v2` lands.
#[derive(NetworkBehaviour)]
pub struct ChunkBehaviour {
    chunks: cbor::Behaviour<ChunkOpRequest, ChunkOpResponse>,
}

impl ChunkBehaviour {
    fn new() -> Self {
        let protocol = StreamProtocol::new(CHUNKS_PROTOCOL);
        let chunks = cbor::Behaviour::<ChunkOpRequest, ChunkOpResponse>::new(
            [(protocol, ProtocolSupport::Full)],
            RrConfig::default().with_request_timeout(Duration::from_secs(60)),
        );
        Self { chunks }
    }
}

/// Handle returned by [`P2pNode::spawn`]. The Swarm runs in a
/// background task; this handle exposes a watch channel of the
/// current listen multiaddrs and a shutdown signal.
pub struct P2pHandle {
    pub multiaddrs: watch::Receiver<Vec<Multiaddr>>,
    pub shutdown: mpsc::Sender<()>,
    pub join: tokio::task::JoinHandle<anyhow::Result<()>>,
}

pub struct P2pNode;

impl P2pNode {
    /// Boot the Swarm, start listening, and run the event loop in a
    /// detached tokio task. The returned `multiaddrs` watch channel
    /// fires once the first listen address is acquired.
    ///
    /// `listen_on` is the libp2p multiaddr to bind on (typically
    /// `/ip4/0.0.0.0/tcp/0` in production, `/ip4/127.0.0.1/tcp/0` in
    /// tests). The acquired multiaddr — appended with the `/p2p/...`
    /// peer suffix — surfaces via the watch channel.
    ///
    /// # Errors
    ///
    /// Swarm-builder / listen-bind / I/O failures.
    pub async fn spawn(
        transport_keypair: identity::Keypair,
        listen_on: Multiaddr,
        storage: Arc<dyn VaultStorage>,
        resolver: Arc<dyn IdentityResolver>,
    ) -> anyhow::Result<P2pHandle> {
        let peer_id = transport_keypair.public().to_peer_id();
        let mut swarm: Swarm<ChunkBehaviour> =
            SwarmBuilder::with_existing_identity(transport_keypair)
                .with_tokio()
                .with_tcp(
                    tcp::Config::default().nodelay(true),
                    noise::Config::new,
                    yamux::Config::default,
                )
                .map_err(|e| anyhow!("tcp transport: {e:?}"))?
                .with_behaviour(|_| ChunkBehaviour::new())
                .map_err(|e| anyhow!("behaviour: {e:?}"))?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
                .build();
        swarm
            .listen_on(listen_on.clone())
            .with_context(|| format!("listen on {listen_on}"))?;

        let (addr_tx, addr_rx) = watch::channel::<Vec<Multiaddr>>(Vec::new());
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        let pubkey_cache: Arc<Mutex<HashMap<(ClusterId, UserId), MlDsa65PublicKey>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let join = tokio::spawn(async move {
            let mut listen_addrs: Vec<Multiaddr> = Vec::new();
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::info!("p2p: shutdown requested");
                        return Ok::<_, anyhow::Error>(());
                    }
                    event = swarm.select_next_some() => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                let full = address.with_p2p(peer_id).unwrap_or_else(|m| m);
                                if !listen_addrs.contains(&full) {
                                    listen_addrs.push(full);
                                    let _ = addr_tx.send(listen_addrs.clone());
                                    tracing::info!(?listen_addrs, "p2p: listening");
                                }
                            }
                            SwarmEvent::ExpiredListenAddr { address, .. } => {
                                let full = address.with_p2p(peer_id).unwrap_or_else(|m| m);
                                listen_addrs.retain(|a| a != &full);
                                let _ = addr_tx.send(listen_addrs.clone());
                            }
                            SwarmEvent::Behaviour(ChunkBehaviourEvent::Chunks(rr_event)) => {
                                if let Err(e) = handle_rr_event(
                                    rr_event,
                                    &mut swarm,
                                    storage.clone(),
                                    resolver.clone(),
                                    pubkey_cache.clone(),
                                )
                                .await
                                {
                                    tracing::warn!(error = %e, "p2p: rr-event handler error");
                                }
                            }
                            other => {
                                tracing::trace!(?other, "p2p: swarm event");
                            }
                        }
                    }
                }
            }
        });

        Ok(P2pHandle {
            multiaddrs: addr_rx,
            shutdown: shutdown_tx,
            join,
        })
    }
}

async fn handle_rr_event(
    event: RrEvent<ChunkOpRequest, ChunkOpResponse>,
    swarm: &mut Swarm<ChunkBehaviour>,
    storage: Arc<dyn VaultStorage>,
    resolver: Arc<dyn IdentityResolver>,
    pubkey_cache: Arc<Mutex<HashMap<(ClusterId, UserId), MlDsa65PublicKey>>>,
) -> anyhow::Result<()> {
    match event {
        RrEvent::Message {
            message: Message::Request {
                request, channel, ..
            },
            ..
        } => {
            let request_id = request.request_id;
            let response =
                match process_request(request, storage.as_ref(), resolver.as_ref(), &pubkey_cache)
                    .await
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::warn!(error = %e, "chunks: request rejected");
                        ChunkOpResponse::Error {
                            request_id,
                            code: e.code,
                            message: e.message,
                        }
                    }
                };
            if swarm
                .behaviour_mut()
                .chunks
                .send_response(channel, response)
                .is_err()
            {
                tracing::warn!("chunks: failed to send response (peer disconnected)");
            }
        }
        RrEvent::Message {
            message: Message::Response { .. },
            ..
        } => {
            // Vault is the server side; we don't expect inbound
            // responses on this protocol.
        }
        RrEvent::OutboundFailure { error, .. } => {
            tracing::trace!(?error, "rr outbound failure");
        }
        RrEvent::InboundFailure { error, .. } => {
            tracing::trace!(?error, "rr inbound failure");
        }
        RrEvent::ResponseSent { .. } => {}
    }
    Ok(())
}

#[derive(Debug)]
struct DispatchError {
    code: u16,
    message: String,
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl DispatchError {
    fn auth(message: impl Into<String>) -> Self {
        Self {
            code: 401,
            message: message.into(),
        }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: 400,
            message: message.into(),
        }
    }
    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: 500,
            message: message.into(),
        }
    }
}

async fn process_request(
    request: ChunkOpRequest,
    storage: &dyn VaultStorage,
    resolver: &dyn IdentityResolver,
    pubkey_cache: &Mutex<HashMap<(ClusterId, UserId), MlDsa65PublicKey>>,
) -> Result<ChunkOpResponse, DispatchError> {
    // Verify the user signature first — every other check is gated
    // on this.
    let pubkey =
        lookup_identity_pubkey(request.cluster_id, request.user_id, resolver, pubkey_cache).await?;
    let signed = chunk_op_signed_bytes(
        request.format_version,
        request.request_id,
        &request.cluster_id,
        &request.user_id,
        &request.op,
        request.created_at_ms,
    )
    .map_err(|e| DispatchError::bad_request(format!("signed-bytes encode: {e}")))?;
    ml_dsa_65_verify(&pubkey, &request.sig_user, &signed)
        .map_err(|_| DispatchError::auth("sig_user invalid"))?;

    // Reject requests with skew > 10 minutes either way — replay/
    // freshness defence. Soft check (clock drift tolerance).
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let skew = now_ms.abs_diff(request.created_at_ms);
    if skew > 10 * 60 * 1000 {
        return Err(DispatchError::bad_request(format!(
            "created_at_ms skew {skew} ms exceeds 10 min"
        )));
    }

    let request_id = request.request_id;
    let owner = request.user_id;
    match request.op {
        ChunkOp::Put { addresses, chunks } => {
            if addresses.len() != chunks.len() {
                return Err(DispatchError::bad_request(
                    "Put.addresses and Put.chunks length mismatch",
                ));
            }
            let mut acked = Vec::with_capacity(addresses.len());
            let mut errors: Vec<(
                vitonomi_core::protocol::autonomi_bridge::ChunkAddress,
                String,
            )> = Vec::new();
            for (addr, bytes) in addresses.into_iter().zip(chunks.into_iter()) {
                match storage.put_chunk(owner, addr.clone(), bytes).await {
                    Ok(()) => acked.push(addr),
                    Err(e) => errors.push((addr, format!("{e}"))),
                }
            }
            Ok(ChunkOpResponse::PutAck {
                request_id,
                acked,
                errors,
            })
        }
        ChunkOp::Get { address } => match storage.get_chunk(&address).await {
            Ok(bytes) => Ok(ChunkOpResponse::GetReply {
                request_id,
                address,
                bytes,
                found: true,
            }),
            Err(CoreError::Storage(StorageError::NotFound)) => Ok(ChunkOpResponse::GetReply {
                request_id,
                address,
                bytes: vec![],
                found: false,
            }),
            Err(e) => Err(DispatchError::internal(format!("get_chunk: {e}"))),
        },
        ChunkOp::List => match storage.list_chunks_for_owner(owner).await {
            Ok(addresses) => Ok(ChunkOpResponse::ListReply {
                request_id,
                addresses,
            }),
            Err(e) => Err(DispatchError::internal(format!("list_chunks: {e}"))),
        },
        ChunkOp::Delete { address } => match storage.delete_chunk(owner, &address).await {
            Ok(()) => Ok(ChunkOpResponse::DeleteAck {
                request_id,
                deleted: true,
            }),
            Err(CoreError::Storage(StorageError::NotFound)) => Ok(ChunkOpResponse::DeleteAck {
                request_id,
                deleted: false,
            }),
            Err(CoreError::Storage(StorageError::OwnerMismatch)) => {
                Err(DispatchError::auth("owner mismatch"))
            }
            Err(e) => Err(DispatchError::internal(format!("delete_chunk: {e}"))),
        },
    }
}

async fn lookup_identity_pubkey(
    cluster_id: ClusterId,
    user_id: UserId,
    resolver: &dyn IdentityResolver,
    cache: &Mutex<HashMap<(ClusterId, UserId), MlDsa65PublicKey>>,
) -> Result<MlDsa65PublicKey, DispatchError> {
    {
        let g = cache.lock().await;
        if let Some(pk) = g.get(&(cluster_id, user_id)) {
            return Ok(pk.clone());
        }
    }
    let pk = resolver
        .lookup(&cluster_id, &user_id)
        .await
        .map_err(|e| DispatchError::auth(format!("identity pubkey lookup: {e}")))?;
    {
        let mut g = cache.lock().await;
        g.insert((cluster_id, user_id), pk.clone());
    }
    Ok(pk)
}

// Silence dead-code warning for `cbor_to_vec` import on builds where
// it's used only in tests / future paths.
#[allow(dead_code)]
fn _keep_cbor_to_vec_in_scope() -> impl Fn() {
    || {
        let _ = cbor_to_vec::<()>(&());
    }
}

// Silence dead-code warning for CryptoError use in error branches we
// reserve for future extensions.
#[allow(dead_code)]
fn _keep_crypto_error() -> CryptoError {
    CryptoError::SignatureInvalid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vitonomi_core::crypto::pq::{ml_dsa_65_keypair, ml_dsa_65_sign};
    use vitonomi_core::crypto::selfencrypt::encrypt;
    use vitonomi_core::protocol::testing::in_memory_storage::InMemoryVaultStorage;
    use vitonomi_core::types::FormatVersion;

    /// Sync test resolver — returns a fixed pubkey for a known user.
    struct FixedResolver {
        cid: ClusterId,
        uid: UserId,
        pk: MlDsa65PublicKey,
    }

    #[async_trait::async_trait]
    impl IdentityResolver for FixedResolver {
        async fn lookup(
            &self,
            cluster_id: &ClusterId,
            user_id: &UserId,
        ) -> Result<MlDsa65PublicKey, anyhow::Error> {
            if cluster_id == &self.cid && user_id == &self.uid {
                Ok(self.pk.clone())
            } else {
                anyhow::bail!("unknown user")
            }
        }
    }

    fn sample_chunk() -> (
        vitonomi_core::crypto::selfencrypt::Chunk,
        Vec<vitonomi_core::crypto::selfencrypt::Chunk>,
    ) {
        let bytes: Vec<u8> = (0..(8 * 1024)).map(|i| (i & 0xff) as u8).collect();
        let (chunks, _) = encrypt(&bytes).unwrap();
        (chunks[0].clone(), chunks)
    }

    fn now_test_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn build_get_request(
        kp_sk: &vitonomi_core::crypto::pq::MlDsa65SecretKey,
        cid: ClusterId,
        uid: UserId,
        addr: vitonomi_core::protocol::autonomi_bridge::ChunkAddress,
    ) -> ChunkOpRequest {
        let op = ChunkOp::Get {
            address: addr.clone(),
        };
        let ts = now_test_ms();
        let signed = chunk_op_signed_bytes(FormatVersion::V1, 1, &cid, &uid, &op, ts).unwrap();
        let sig = ml_dsa_65_sign(kp_sk, &signed).unwrap();
        ChunkOpRequest {
            format_version: FormatVersion::V1,
            request_id: 1,
            cluster_id: cid,
            user_id: uid,
            op,
            created_at_ms: ts,
            sig_user: sig,
        }
    }

    #[tokio::test]
    async fn process_request_rejects_bad_signature() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = ClusterId([1u8; 32]);
        let uid = UserId([2u8; 16]);
        let resolver = FixedResolver {
            cid,
            uid,
            pk: kp.public.clone(),
        };
        let storage: Arc<dyn VaultStorage> = Arc::new(InMemoryVaultStorage::new());
        let cache: Mutex<HashMap<(ClusterId, UserId), MlDsa65PublicKey>> =
            Mutex::new(HashMap::new());

        let mut req = build_get_request(
            &kp.secret,
            cid,
            uid,
            vitonomi_core::protocol::autonomi_bridge::ChunkAddress([0u8; 32]),
        );
        req.sig_user.0[0] ^= 0x01;
        let result = process_request(req, storage.as_ref(), &resolver, &cache).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().code, 401);
    }

    #[tokio::test]
    async fn process_request_round_trip_put_then_get() {
        let kp = ml_dsa_65_keypair().unwrap();
        let cid = ClusterId([1u8; 32]);
        let uid = UserId([2u8; 16]);
        let resolver = FixedResolver {
            cid,
            uid,
            pk: kp.public.clone(),
        };
        let storage: Arc<dyn VaultStorage> = Arc::new(InMemoryVaultStorage::new());
        let cache: Mutex<HashMap<(ClusterId, UserId), MlDsa65PublicKey>> =
            Mutex::new(HashMap::new());

        let (first, all_chunks) = sample_chunk();

        // PUT
        let put_op = ChunkOp::Put {
            addresses: all_chunks.iter().map(|c| c.address.clone()).collect(),
            chunks: all_chunks.iter().map(|c| c.bytes.clone()).collect(),
        };
        let ts = now_test_ms();
        let signed = chunk_op_signed_bytes(FormatVersion::V1, 7, &cid, &uid, &put_op, ts).unwrap();
        let sig = ml_dsa_65_sign(&kp.secret, &signed).unwrap();
        let put_req = ChunkOpRequest {
            format_version: FormatVersion::V1,
            request_id: 7,
            cluster_id: cid,
            user_id: uid,
            op: put_op,
            created_at_ms: ts,
            sig_user: sig,
        };
        match process_request(put_req, storage.as_ref(), &resolver, &cache)
            .await
            .unwrap()
        {
            ChunkOpResponse::PutAck { acked, errors, .. } => {
                assert_eq!(acked.len(), all_chunks.len());
                assert!(errors.is_empty());
            }
            other => panic!("expected PutAck, got {other:?}"),
        }

        // GET the first chunk back.
        let get_req = build_get_request(&kp.secret, cid, uid, first.address.clone());
        match process_request(get_req, storage.as_ref(), &resolver, &cache)
            .await
            .unwrap()
        {
            ChunkOpResponse::GetReply { bytes, found, .. } => {
                assert!(found);
                assert_eq!(bytes, first.bytes);
            }
            other => panic!("expected GetReply, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn load_or_generate_persists_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let kp1 = load_or_generate_transport_keypair(dir.path()).unwrap();
        let kp2 = load_or_generate_transport_keypair(dir.path()).unwrap();
        assert_eq!(kp1.public().to_peer_id(), kp2.public().to_peer_id());
    }

    #[tokio::test]
    async fn spawn_starts_listening_and_emits_addr() {
        let dir = tempfile::tempdir().unwrap();
        let kp = load_or_generate_transport_keypair(dir.path()).unwrap();
        let public_kp = ml_dsa_65_keypair().unwrap();
        let resolver = Arc::new(FixedResolver {
            cid: ClusterId([0u8; 32]),
            uid: UserId([0u8; 16]),
            pk: public_kp.public,
        });
        let storage: Arc<dyn VaultStorage> = Arc::new(InMemoryVaultStorage::new());
        let handle = P2pNode::spawn(
            kp,
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            storage,
            resolver,
        )
        .await
        .unwrap();
        // Wait for the watch channel to fire.
        let mut rx = handle.multiaddrs.clone();
        for _ in 0..40 {
            if !rx.borrow().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let addrs = rx.borrow().clone();
        assert!(!addrs.is_empty(), "swarm should have a listen addr");
        assert!(
            addrs.iter().any(|a| a.to_string().contains("/tcp/")),
            "expected a /tcp/ address, got {addrs:?}"
        );
        let _ = handle.shutdown.send(()).await;
        let _ = handle.join.await;
    }
}
