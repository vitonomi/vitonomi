//! Thin HTTP wrappers over the hub's `/v1` surface. Uses the
//! system trust store (or `--insecure` for dev / self-signed
//! certs in tests). For integration tests with the hub running
//! plain HTTP, a default `reqwest::Client` works as-is.

use anyhow::{Context as _, Result};
use reqwest::Client;

use vitonomi_core::protocol::hub_control_plane::{
    ClusterRegisterRequest, ClusterRegisterResponse, ClusterRestoreRequest,
};
use vitonomi_core::protocol::wire::accept::{CreateInviteRequest, CreateInviteResponse};
use vitonomi_core::protocol::wire::login::{
    LoginFinishRequest, LoginFinishResponse, LoginStartRequest, LoginStartResponse,
};
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
