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
        .context("send /v1/clusters")?
        .error_for_status()
        .context("/v1/clusters status")?
        .json()
        .await
        .context("decode /v1/clusters response")?;
    Ok(resp)
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
        .context("send /v1/clusters/restore")?
        .error_for_status()
        .context("/v1/clusters/restore status")?
        .json()
        .await
        .context("decode /v1/clusters/restore response")?;
    Ok(resp)
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
        .context("send /v1/auth/login/start")?
        .error_for_status()
        .context("/v1/auth/login/start status")?
        .json()
        .await
        .context("decode /v1/auth/login/start response")?;
    Ok(resp)
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
        .context("send /v1/auth/login/finish")?
        .error_for_status()
        .context("/v1/auth/login/finish status")?
        .json()
        .await
        .context("decode /v1/auth/login/finish response")?;
    Ok(resp)
}

pub async fn logout(client: &Client, hub_url: &str, bearer: &str) -> Result<()> {
    let url = format!("{}/v1/auth/logout", hub_url.trim_end_matches('/'));
    client
        .post(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send /v1/auth/logout")?
        .error_for_status()
        .context("/v1/auth/logout status")?;
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
        .context("send /v1/vaults/invites")?
        .error_for_status()
        .context("/v1/vaults/invites status")?
        .json()
        .await
        .context("decode /v1/vaults/invites response")?;
    Ok(resp)
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
        .context("send /v1/vaults")?
        .error_for_status()
        .context("/v1/vaults status")?
        .json()
        .await
        .context("decode /v1/vaults response")?;
    Ok(resp)
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
        .context("send /v1/admin-chain/_/head")?
        .error_for_status()
        .context("/v1/admin-chain/_/head status")?
        .json()
        .await
        .context("decode /v1/admin-chain/_/head response")?;
    Ok(resp)
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

// ---------- Phase 7: subdomain / domain / alias / inbox ----------

pub async fn claim_subdomain(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    claim: &SubdomainClaim,
) -> Result<()> {
    let url = format!("{}/v1/subdomains", hub_url.trim_end_matches('/'));
    client
        .post(url)
        .bearer_auth(bearer)
        .json(claim)
        .send()
        .await
        .context("send /v1/subdomains")?
        .error_for_status()
        .context("/v1/subdomains status")?;
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
    client
        .delete(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send DELETE /v1/subdomains")?
        .error_for_status()
        .context("DELETE /v1/subdomains status")?;
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
        .context("send GET /v1/subdomains")?
        .error_for_status()
        .context("GET /v1/subdomains status")?
        .json()
        .await
        .context("decode SubdomainDirectoryEntry")?;
    Ok(resp)
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
        .context("send /v1/managed-base-domains")?
        .error_for_status()
        .context("/v1/managed-base-domains status")?
        .json()
        .await
        .context("decode ManagedBaseDomains")?;
    Ok(resp)
}

#[derive(serde::Serialize)]
struct AddCustomDomainRequest<'a> {
    domain: &'a str,
}

pub async fn add_custom_domain(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    domain: &str,
) -> Result<DomainChallenge> {
    let url = format!("{}/v1/domains", hub_url.trim_end_matches('/'));
    let resp = client
        .post(url)
        .bearer_auth(bearer)
        .json(&AddCustomDomainRequest { domain })
        .send()
        .await
        .context("send POST /v1/domains")?
        .error_for_status()
        .context("POST /v1/domains status")?
        .json()
        .await
        .context("decode DomainChallenge")?;
    Ok(resp)
}

pub async fn verify_custom_domain(
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
        .context("send POST /v1/domains/_/verify")?
        .error_for_status()
        .context("POST /v1/domains/_/verify status")?
        .json()
        .await
        .context("decode DomainVerified")?;
    Ok(resp)
}

#[derive(serde::Deserialize)]
pub struct ListDomainsResponse {
    pub domains: Vec<DomainRecord>,
}

pub async fn list_custom_domains(
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
        .context("send GET /v1/domains")?
        .error_for_status()
        .context("GET /v1/domains status")?
        .json()
        .await
        .context("decode ListDomainsResponse")?;
    Ok(resp)
}

pub async fn remove_custom_domain(
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
    client
        .delete(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send DELETE /v1/domains")?
        .error_for_status()
        .context("DELETE /v1/domains status")?;
    Ok(())
}

pub async fn publish_alias_pubkey(
    client: &Client,
    hub_url: &str,
    bearer: &str,
    entry: &AliasDirectoryEntry,
) -> Result<()> {
    let url = format!("{}/v1/aliases/directory", hub_url.trim_end_matches('/'));
    client
        .post(url)
        .bearer_auth(bearer)
        .json(entry)
        .send()
        .await
        .context("send POST /v1/aliases/directory")?
        .error_for_status()
        .context("POST /v1/aliases/directory status")?;
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
    let body: AliasDirectoryEntry = resp
        .error_for_status()
        .context("GET /v1/aliases/directory status")?
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
    client
        .delete(url)
        .bearer_auth(bearer)
        .send()
        .await
        .context("send DELETE /v1/aliases/directory")?
        .error_for_status()
        .context("DELETE /v1/aliases/directory status")?;
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
        .context("send GET /v1/aliases/_/inbox")?
        .error_for_status()
        .context("GET /v1/aliases/_/inbox status")?
        .json()
        .await
        .context("decode InboxFetchResponse")?;
    Ok(resp)
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
    client
        .post(url)
        .bearer_auth(bearer)
        .json(&InboxAckRequest { up_to_seq })
        .send()
        .await
        .context("send POST /v1/aliases/_/inbox/ack")?
        .error_for_status()
        .context("POST /v1/aliases/_/inbox/ack status")?;
    Ok(())
}
