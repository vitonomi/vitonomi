//! HTTP + WebSocket client for vault → hub. Uses a custom
//! `rustls::client::ServerCertVerifier` that pins the leaf cert's
//! SPKI hash to `hub.cert_fingerprint` from `vault.toml`. System
//! trust store is bypassed entirely — same code path for dev
//! self-signed certs and prod CA-issued certs.
//!
//! Reconnection on the WS path uses exponential backoff capped at
//! 60 s; reset on every successful `SessionEstablished`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use vitonomi_core::protocol::wire::accept::{
    AcceptRequest, AcceptResponse, CreateInviteRequest, CreateInviteResponse,
};
use vitonomi_core::protocol::wire::bootstrap::{BootstrapRequest, BootstrapResponse};
use vitonomi_core::protocol::wire::vault_bus::BusFrame;

/// Construct a `reqwest::Client` that pins the hub's TLS leaf cert
/// SPKI to `expected_fingerprint`. The fingerprint is the form
/// `sha256:<base64url-no-padding>` exactly as it appears in
/// `vault.toml`.
///
/// # Errors
///
/// Returns `anyhow::Error` on rustls config build failure.
pub fn pinned_http_client(expected_fingerprint: &str) -> anyhow::Result<reqwest::Client> {
    let verifier = SpkiPinningVerifier::new(expected_fingerprint)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(Duration::from_secs(30))
        .build()
        .context("build pinned reqwest client")?;
    Ok(client)
}

/// Submit a `CreateInviteRequest` to `/v1/vaults/invites` (admin-only).
///
/// # Errors
///
/// Network / status / decode failures.
pub async fn create_invite(
    client: &reqwest::Client,
    hub_url: &str,
    bearer: &str,
    req: &CreateInviteRequest,
) -> anyhow::Result<CreateInviteResponse> {
    let url = format!("{}/v1/vaults/invites", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .json(req)
        .send()
        .await
        .context("send create_invite")?
        .error_for_status()
        .context("create_invite status")?
        .json()
        .await
        .context("decode create_invite response")?;
    Ok(resp)
}

/// Submit an `AcceptRequest` to `/v1/vaults/accept` (unauthenticated).
///
/// # Errors
///
/// Network / status / decode failures.
pub async fn accept_invite(
    client: &reqwest::Client,
    hub_url: &str,
    req: &AcceptRequest,
) -> anyhow::Result<AcceptResponse> {
    let url = format!("{}/v1/vaults/accept", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .context("send accept")?
        .error_for_status()
        .context("accept status")?
        .json()
        .await
        .context("decode accept response")?;
    Ok(resp)
}

/// Submit a `BootstrapRequest` to `/v1/clusters/bootstrap`. Used by
/// the vault on `start` so a hub that has lost its cluster record
/// (typical after an `InMemoryHub` reboot) can re-create it from the
/// vault's chain copy + persisted membership proof. Idempotent: the
/// hub returns the existing `vault_id` if the cluster + vault are
/// already registered.
///
/// # Errors
///
/// Network / status / decode failures.
pub async fn bootstrap_cluster(
    client: &reqwest::Client,
    hub_url: &str,
    req: &BootstrapRequest,
) -> anyhow::Result<BootstrapResponse> {
    let url = format!("{}/v1/clusters/bootstrap", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .context("send bootstrap")?
        .error_for_status()
        .context("bootstrap status")?
        .json()
        .await
        .context("decode bootstrap response")?;
    Ok(resp)
}

/// Fetch the cluster admin pubkey by reading the current chain head
/// off the hub. Used by `set_hub` to verify that the new hub speaks
/// for the same cluster before rewriting `vault.toml`.
///
/// # Errors
///
/// Network / status / decode failures.
pub async fn get_admin_chain_head(
    client: &reqwest::Client,
    hub_url: &str,
    bearer: &str,
    cluster_id_hex: &str,
) -> anyhow::Result<vitonomi_core::protocol::wire::admin_chain::ChainHeadResponse> {
    let url = format!(
        "{}/v1/admin-chain/{}/head",
        hub_url.trim_end_matches('/'),
        cluster_id_hex
    );
    let resp = client
        .get(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send chain head")?
        .error_for_status()
        .context("chain head status")?
        .json()
        .await
        .context("decode chain head response")?;
    Ok(resp)
}

/// Encode a `BusFrame` as length-prefixed CBOR.
pub fn encode_frame(frame: &BusFrame) -> anyhow::Result<Vec<u8>> {
    let cbor =
        vitonomi_core::encoding::cbor_to_vec(frame).map_err(|e| anyhow!("encode CBOR: {e}"))?;
    let len: u32 = u32::try_from(cbor.len()).map_err(|_| anyhow!("frame too large"))?;
    let mut out = Vec::with_capacity(4 + cbor.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&cbor);
    Ok(out)
}

/// Decode a length-prefixed CBOR `BusFrame`.
pub fn decode_frame(bytes: &[u8]) -> anyhow::Result<BusFrame> {
    if bytes.len() < 4 {
        return Err(anyhow!("frame too short"));
    }
    let len_arr: [u8; 4] = bytes[..4].try_into().expect("len prefix slice");
    let len = u32::from_le_bytes(len_arr) as usize;
    if bytes.len() != 4 + len {
        return Err(anyhow!(
            "len prefix mismatch: header says {len}, body is {}",
            bytes.len() - 4
        ));
    }
    vitonomi_core::encoding::cbor_from_slice(&bytes[4..])
        .map_err(|e| anyhow!("decode CBOR frame: {e}"))
}

/// Initial backoff before the first reconnect attempt.
pub const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Cap on backoff between attempts.
pub const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Compute the next backoff value (doubling, capped).
#[must_use]
pub fn next_backoff(current: Duration) -> Duration {
    let next = current.saturating_mul(2);
    if next > RECONNECT_BACKOFF_MAX {
        RECONNECT_BACKOFF_MAX
    } else {
        next
    }
}

// ─── SPKI-pinning rustls verifier ──────────────────────────────────

/// Custom verifier: trust *only* a leaf cert whose SPKI hash matches
/// the configured fingerprint. System trust store is bypassed.
#[derive(Debug)]
struct SpkiPinningVerifier {
    expected: [u8; 32],
}

impl SpkiPinningVerifier {
    fn new(fingerprint: &str) -> anyhow::Result<Self> {
        let b64 = fingerprint
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("fingerprint must start with `sha256:`"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(b64.as_bytes())
            .map_err(|e| anyhow!("decode fingerprint base64url: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!("expected 32-byte SHA-256, got {}", bytes.len()));
        }
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&bytes);
        Ok(Self { expected })
    }
}

impl ServerCertVerifier for SpkiPinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki = extract_spki(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("could not extract SPKI from leaf cert".into())
        })?;
        let mut h = Sha256::new();
        h.update(spki);
        let actual = h.finalize();
        if actual.as_slice() == self.expected.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "SPKI fingerprint mismatch: expected {} got {}",
                URL_SAFE_NO_PAD.encode(self.expected),
                URL_SAFE_NO_PAD.encode(actual)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

pub(crate) fn extract_spki_pub(cert_der: &[u8]) -> Option<&[u8]> {
    extract_spki(cert_der)
}

fn extract_spki(cert_der: &[u8]) -> Option<&[u8]> {
    let mut p = Asn1Parser {
        buf: cert_der,
        pos: 0,
    };
    let cert_body = p.read_seq()?;
    let mut tbs_p = Asn1Parser {
        buf: cert_body,
        pos: 0,
    };
    let tbs_body = tbs_p.read_seq()?;
    let mut tbs = Asn1Parser {
        buf: tbs_body,
        pos: 0,
    };
    if tbs.peek_tag() == Some(0xa0) {
        tbs.read_tlv()?;
    }
    tbs.read_tlv()?; // serialNumber
    tbs.read_tlv()?; // signature alg
    tbs.read_tlv()?; // issuer
    tbs.read_tlv()?; // validity
    tbs.read_tlv()?; // subject
    tbs.read_tlv_with_header()
}

struct Asn1Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Asn1Parser<'a> {
    fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }
    fn read_seq(&mut self) -> Option<&'a [u8]> {
        let tag = self.read_byte()?;
        if tag != 0x30 {
            return None;
        }
        let len = self.read_len()?;
        let s = self.pos;
        let e = s.checked_add(len)?;
        if e > self.buf.len() {
            return None;
        }
        self.pos = e;
        Some(&self.buf[s..e])
    }
    fn read_tlv(&mut self) -> Option<&'a [u8]> {
        let _ = self.read_byte()?;
        let len = self.read_len()?;
        let s = self.pos;
        let e = s.checked_add(len)?;
        if e > self.buf.len() {
            return None;
        }
        self.pos = e;
        Some(&self.buf[s..e])
    }
    fn read_tlv_with_header(&mut self) -> Option<&'a [u8]> {
        let h = self.pos;
        let _ = self.read_byte()?;
        let len = self.read_len()?;
        let s = self.pos;
        let e = s.checked_add(len)?;
        if e > self.buf.len() {
            return None;
        }
        self.pos = e;
        Some(&self.buf[h..e])
    }
    fn read_byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn read_len(&mut self) -> Option<usize> {
        let b = self.read_byte()?;
        if b & 0x80 == 0 {
            return Some(b as usize);
        }
        let n = (b & 0x7f) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | (self.read_byte()? as usize);
        }
        Some(len)
    }
}
