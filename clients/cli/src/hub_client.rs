//! Thin HTTP wrappers over the hub's `/v1` surface. Uses the
//! system trust store (or `--insecure` for dev / self-signed
//! certs in tests). For integration tests with the hub running
//! plain HTTP, a default `reqwest::Client` works as-is.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context as _, Result};
use reqwest::Client;

use vitonomi_core::protocol::hub_control_plane::{
    ClusterRegisterRequest, ClusterRegisterResponse, ClusterRestoreRequest,
};
use vitonomi_core::protocol::wire::accept::{CreateInviteRequest, CreateInviteResponse};
use vitonomi_core::protocol::wire::aliases::{AliasDirectoryEntry, InboundEnvelope};
use vitonomi_core::protocol::wire::domains::{DomainChallenge, DomainRecord, DomainVerified};
use vitonomi_core::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
};
use vitonomi_core::protocol::wire::mx_relay_push::RegisterMxRelayRequest;
use vitonomi_core::protocol::wire::subdomains::{ManagedBaseDomains, SubdomainDirectoryEntry};
use vitonomi_core::record::RecordId;
use vitonomi_core::types::subdomain::{Subdomain, SubdomainClaim};
use vitonomi_core::types::ClusterId;

/// Default insecure (system-trust-only) HTTP client for hub calls.
/// Production deployments should swap in an SPKI-pinned client.
pub fn default_client() -> Result<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()
        .context("build cli HTTP client")
}

/// Shape of the hub's structured error response. All routes serialise
/// `hub::routes::errors::ApiError` to this JSON body.
#[derive(serde::Deserialize)]
struct ApiErrorBody {
    code: String,
    message: String,
}

/// If `resp` is non-2xx, drain the body, try to parse it as the hub's
/// `{code, message}` error envelope, and surface both fields in the
/// resulting `anyhow::Error`. Use instead of `.error_for_status()` so
/// the hub's reason for rejecting a request actually reaches the user.
///
/// `op_label` is included verbatim in the error (e.g.
/// `"POST /v1/subdomains"`) so the chain reads naturally.
async fn check_status(
    resp: reqwest::Response,
    op_label: &'static str,
) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if let Ok(api_err) = serde_json::from_str::<ApiErrorBody>(&body) {
        return Err(anyhow!(
            "{op_label}: {} (code={}, status={})",
            api_err.message,
            api_err.code,
            status.as_u16(),
        ));
    }
    let body_excerpt = if body.is_empty() {
        String::new()
    } else {
        format!(": {}", body.chars().take(200).collect::<String>())
    };
    Err(anyhow!("{op_label}: HTTP {status}{body_excerpt}"))
}

/// Probe the hub's TLS leaf cert, return the canonical
/// `sha256:<base64url-no-padding>` SPKI fingerprint. Implements
/// trust-on-first-use: any cert is accepted during the handshake;
/// the fingerprint is computed from the cert bytes captured on the
/// way through. `http://` URLs return an explicit error since
/// there's no TLS to probe.
///
/// # Errors
///
/// Network / handshake failures or attempts to probe a `http://`
/// hub.
pub async fn fetch_hub_fingerprint(hub_url: &str) -> Result<String> {
    if hub_url.starts_with("http://") {
        return Err(anyhow!(
            "cannot probe TLS fingerprint of plain-http hub {hub_url}"
        ));
    }

    // Custom verifier: capture the leaf cert bytes during the
    // handshake while accepting any cert (TOFU — the pinning happens
    // *after* this probe, by virtue of the user-confirmed value
    // being persisted into cli.toml).
    let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let verifier = CapturingVerifier {
        captured: captured.clone(),
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let client = Client::builder()
        .use_preconfigured_tls(tls)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("build cert-capture client")?;

    // Cheapest possible exchange that triggers a full TLS handshake.
    // Body and status are irrelevant — we only need the cert.
    let url = format!("{}/v1/status", hub_url.trim_end_matches('/'));
    let _ = client.get(&url).send().await;

    let leaf = captured
        .lock()
        .map_err(|e| anyhow!("captured cert mutex poisoned: {e}"))?
        .clone()
        .ok_or_else(|| anyhow!("no leaf cert captured during TLS handshake to {hub_url}"))?;
    vitonomi_core::crypto::spki::fingerprint_for_cert(&leaf)
        .ok_or_else(|| anyhow!("malformed leaf cert: SPKI extraction failed"))
}

#[derive(Debug)]
struct CapturingVerifier {
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}

impl rustls::client::danger::ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(end_entity.as_ref().to_vec());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

pub async fn register_cluster(
    client: &Client,
    hub_url: &str,
    req: &ClusterRegisterRequest,
) -> Result<ClusterRegisterResponse> {
    let url = format!("{}/v1/clusters", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .context("send POST /v1/clusters")?;
    let resp = check_status(resp, "POST /v1/clusters").await?;
    resp.json().await.context("decode /v1/clusters response")
}

pub async fn restore_cluster(
    client: &Client,
    hub_url: &str,
    req: &ClusterRestoreRequest,
) -> Result<ClusterRegisterResponse> {
    let url = format!("{}/v1/clusters/restore", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .context("send POST /v1/clusters/restore")?;
    let resp = check_status(resp, "POST /v1/clusters/restore").await?;
    resp.json()
        .await
        .context("decode /v1/clusters/restore response")
}

pub async fn login_start(
    client: &Client,
    hub_url: &str,
    req: &LoginStartRequest,
) -> Result<LoginStartResponse> {
    let url = format!("{}/v1/auth/login/start", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .context("send POST /v1/auth/login/start")?;
    let resp = check_status(resp, "POST /v1/auth/login/start").await?;
    resp.json()
        .await
        .context("decode /v1/auth/login/start response")
}

pub async fn login_finish(
    client: &Client,
    hub_url: &str,
    req: &LoginFinishRequest,
) -> Result<LoginFinishResponse> {
    let url = format!("{}/v1/auth/login/finish", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(req)
        .send()
        .await
        .context("send POST /v1/auth/login/finish")?;
    let resp = check_status(resp, "POST /v1/auth/login/finish").await?;
    resp.json()
        .await
        .context("decode /v1/auth/login/finish response")
}

pub async fn logout(client: &Client, hub_url: &str, bearer: &str) -> Result<()> {
    let url = format!("{}/v1/auth/logout", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send POST /v1/auth/logout")?;
    let _ = check_status(resp, "POST /v1/auth/logout").await?;
    Ok(())
}

pub async fn create_invite(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    req: &CreateInviteRequest,
) -> Result<CreateInviteResponse> {
    let url = format!("{}/v1/vaults/invites", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .json(req)
        .send()
        .await
        .context("send POST /v1/vaults/invites")?;
    let resp = check_status(resp, "POST /v1/vaults/invites").await?;
    resp.json()
        .await
        .context("decode /v1/vaults/invites response")
}

/// Register a `vitonomi-mx` relay identity with the hub. Admin-only:
/// the hub gates on `BearerSession` + cluster-admin role. The hub
/// responds with `204 No Content`; the mx-relay's `MxRelayId` is
/// derived locally from the pubkey via `MxRelayId::from_pubkey`, so
/// nothing has to come back over the wire.
pub async fn register_mx_relay(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    req: &RegisterMxRelayRequest,
) -> Result<()> {
    let url = format!("{}/v1/admin/mx-relays", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .json(req)
        .send()
        .await
        .context("send POST /v1/admin/mx-relays")?;
    let _ = check_status(resp, "POST /v1/admin/mx-relays").await?;
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
pub struct ListVaultsResponse {
    pub vaults: Vec<vitonomi_core::protocol::hub_control_plane::VaultRecord>,
}

pub async fn list_vaults(
    client: &Client,
    hub_url: &str,
    bearer: &str,
) -> Result<ListVaultsResponse> {
    let url = format!("{}/v1/vaults", hub_url.trim_end_matches('/'));
    let resp = client
        .get(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send GET /v1/vaults")?;
    let resp = check_status(resp, "GET /v1/vaults").await?;
    resp.json().await.context("decode /v1/vaults response")
}

pub async fn get_admin_chain_head(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    cluster_id: &ClusterId,
) -> Result<vitonomi_core::protocol::wire::admin_chain::ChainHeadResponse> {
    let url = format!(
        "{}/v1/admin-chain/{}/head",
        hub_url.trim_end_matches('/'),
        hex_lower(cluster_id.as_bytes())
    );
    let resp = client
        .get(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send GET /v1/admin-chain/_/head")?;
    let resp = check_status(resp, "GET /v1/admin-chain/_/head").await?;
    resp.json()
        .await
        .context("decode /v1/admin-chain/_/head response")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------- subdomain / domain / alias / inbox ----------

pub async fn claim_subdomain(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    claim: &SubdomainClaim,
) -> Result<()> {
    let url = format!("{}/v1/subdomains", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .json(claim)
        .send()
        .await
        .context("send POST /v1/subdomains")?;
    let _ = check_status(resp, "POST /v1/subdomains").await?;
    Ok(())
}

pub async fn release_subdomain(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    base: &str,
    sub: &Subdomain,
) -> Result<()> {
    let url = format!(
        "{}/v1/subdomains/{}/{}",
        hub_url.trim_end_matches('/'),
        urlencode(base),
        urlencode(sub.as_str())
    );
    let resp = client
        .delete(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send DELETE /v1/subdomains")?;
    let _ = check_status(resp, "DELETE /v1/subdomains").await?;
    Ok(())
}

pub async fn lookup_subdomain(
    client: &Client,
    hub_url: &str,
    base: &str,
    sub: &Subdomain,
) -> Result<SubdomainDirectoryEntry> {
    let url = format!(
        "{}/v1/subdomains/{}/{}",
        hub_url.trim_end_matches('/'),
        urlencode(base),
        urlencode(sub.as_str())
    );
    let resp = client
        .get(url)
        .send()
        .await
        .context("send GET /v1/subdomains")?;
    let resp = check_status(resp, "GET /v1/subdomains").await?;
    resp.json().await.context("decode SubdomainDirectoryEntry")
}

pub async fn list_managed_base_domains(
    client: &Client,
    hub_url: &str,
) -> Result<ManagedBaseDomains> {
    let url = format!("{}/v1/managed-base-domains", hub_url.trim_end_matches('/'));
    let resp = client
        .get(url)
        .send()
        .await
        .context("send GET /v1/managed-base-domains")?;
    let resp = check_status(resp, "GET /v1/managed-base-domains").await?;
    resp.json().await.context("decode ManagedBaseDomains")
}

#[derive(serde::Serialize)]
struct AddDomainRequest<'a> {
    domain: &'a str,
}

pub async fn add_domain(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    domain: &str,
) -> Result<DomainChallenge> {
    let url = format!("{}/v1/domains", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .json(&AddDomainRequest { domain })
        .send()
        .await
        .context("send POST /v1/domains")?;
    let resp = check_status(resp, "POST /v1/domains").await?;
    resp.json().await.context("decode DomainChallenge")
}

pub async fn verify_domain(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    domain: &str,
) -> Result<DomainVerified> {
    let url = format!(
        "{}/v1/domains/{}/verify",
        hub_url.trim_end_matches('/'),
        urlencode(domain)
    );
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send POST /v1/domains/_/verify")?;
    let resp = check_status(resp, "POST /v1/domains/_/verify").await?;
    resp.json().await.context("decode DomainVerified")
}

#[derive(serde::Deserialize)]
pub struct ListDomainsResponse {
    pub domains: Vec<DomainRecord>,
}

pub async fn list_domains(
    client: &Client,
    hub_url: &str,
    bearer: &str,
) -> Result<ListDomainsResponse> {
    let url = format!("{}/v1/domains", hub_url.trim_end_matches('/'));
    let resp = client
        .get(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send GET /v1/domains")?;
    let resp = check_status(resp, "GET /v1/domains").await?;
    resp.json().await.context("decode ListDomainsResponse")
}

pub async fn remove_domain(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    domain: &str,
) -> Result<()> {
    let url = format!(
        "{}/v1/domains/{}",
        hub_url.trim_end_matches('/'),
        urlencode(domain)
    );
    let resp = client
        .delete(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send DELETE /v1/domains")?;
    let _ = check_status(resp, "DELETE /v1/domains").await?;
    Ok(())
}

pub async fn publish_alias_pubkey(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    entry: &AliasDirectoryEntry,
) -> Result<()> {
    let url = format!("{}/v1/aliases/directory", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .json(entry)
        .send()
        .await
        .context("send POST /v1/aliases/directory")?;
    let _ = check_status(resp, "POST /v1/aliases/directory").await?;
    Ok(())
}

pub async fn lookup_alias_pubkey(
    client: &Client,
    hub_url: &str,
    alias_handle: &str,
    namespace: &str,
) -> Result<Option<AliasDirectoryEntry>> {
    let url = format!(
        "{}/v1/aliases/directory/{}/{}",
        hub_url.trim_end_matches('/'),
        urlencode(alias_handle),
        urlencode(namespace)
    );
    let resp = client
        .get(url)
        .send()
        .await
        .context("send GET /v1/aliases/directory")?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let resp = check_status(resp, "GET /v1/aliases/directory").await?;
    let body: AliasDirectoryEntry = resp
        .json()
        .await
        .context("decode AliasDirectoryEntry")?;
    Ok(Some(body))
}

pub async fn revoke_alias_pubkey(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    alias_handle: &str,
    namespace: &str,
) -> Result<()> {
    let url = format!(
        "{}/v1/aliases/directory/{}/{}",
        hub_url.trim_end_matches('/'),
        urlencode(alias_handle),
        urlencode(namespace)
    );
    let resp = client
        .delete(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send DELETE /v1/aliases/directory")?;
    let _ = check_status(resp, "DELETE /v1/aliases/directory").await?;
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct InboxFetchResponse {
    pub envelopes: Vec<InboundEnvelope>,
}

pub async fn fetch_alias_inbox(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    alias_id: &RecordId,
    since_seq: u64,
) -> Result<InboxFetchResponse> {
    let url = format!(
        "{}/v1/aliases/{}/inbox?since={}",
        hub_url.trim_end_matches('/'),
        hex_lower(&alias_id.0),
        since_seq
    );
    let resp = client
        .get(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send GET /v1/aliases/_/inbox")?;
    let resp = check_status(resp, "GET /v1/aliases/_/inbox").await?;
    resp.json().await.context("decode InboxFetchResponse")
}

#[derive(serde::Serialize)]
struct InboxAckRequest {
    up_to_seq: u64,
}

pub async fn ack_alias_inbox(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    alias_id: &RecordId,
    up_to_seq: u64,
) -> Result<()> {
    let url = format!(
        "{}/v1/aliases/{}/inbox/ack",
        hub_url.trim_end_matches('/'),
        hex_lower(&alias_id.0)
    );
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .json(&InboxAckRequest { up_to_seq })
        .send()
        .await
        .context("send POST /v1/aliases/_/inbox/ack")?;
    let _ = check_status(resp, "POST /v1/aliases/_/inbox/ack").await?;
    Ok(())
}
