//! Pins the contract that hub error responses (JSON body with
//! `{code, message}`) propagate end-to-end into the CLI's
//! `anyhow::Error` chain. Without this, hub-side rejection reasons
//! get swallowed by `reqwest::Response::error_for_status` and the
//! user only sees an opaque HTTP status.
//!
//! Trigger: two `subdomain claim` calls under the same managed base.
//! The second hits the in-memory hub's one-per-cluster-per-base gate
//! and returns 400 with body
//! `{"code": "validation.invalid", "message":
//! "subdomain.cluster_already_claimed_in_base: vito.gg"}`. The CLI
//! must surface both `cluster_already_claimed_in_base` and the
//! structured `code` so the user can act on it.

use std::time::Duration;

use vitonomi_cli::commands::subdomain_claim::{run as cli_subdomain_claim, SubdomainClaimArgs};
use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;
use vitonomi_vault::config::VaultConfig;

use vitonomi_integration::harness::{
    boot_hub, run_cluster_create, run_vault_invite, setup_admin, setup_and_accept_vault_with,
    AdminContext, VaultSetupOpts,
};

const PASSWORD: &str = "hub-error-propagation-e2e-pw";

fn pw() -> ScriptedPrompts {
    ScriptedPrompts {
        username: "birkeal".into(),
        password: PASSWORD.into(),
        seed_phrase: String::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subdomain_claim_collision_surfaces_hub_message() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, admin, _vault_task) = boot_full_stack(temp.path()).await;
    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let _ = hub_url;

    // First claim under vito.gg — succeeds.
    let mut prompts = pw();
    cli_subdomain_claim(
        &cfg,
        SubdomainClaimArgs {
            state_path: &admin.cli_state_path,
            subdomain: "first".into(),
            base_domain: "vito.gg".into(),
        },
        &mut prompts,
    )
    .await
    .expect("first claim succeeds");

    // Second claim under the SAME base — hits the
    // one-per-cluster-per-base gate and the hub returns 400.
    let mut prompts = pw();
    let err = cli_subdomain_claim(
        &cfg,
        SubdomainClaimArgs {
            state_path: &admin.cli_state_path,
            subdomain: "second".into(),
            base_domain: "vito.gg".into(),
        },
        &mut prompts,
    )
    .await
    .expect_err("second claim must fail with hub rejection");

    let chained = format!("{err:#}");
    assert!(
        chained.contains("cluster_already_claimed_in_base"),
        "expected hub message in error chain, got: {chained}"
    );
    assert!(
        chained.contains("code=validation.invalid"),
        "expected structured code in error chain, got: {chained}"
    );
    assert!(
        chained.contains("status=400"),
        "expected HTTP status in error chain, got: {chained}"
    );
}

async fn boot_full_stack(
    temp: &std::path::Path,
) -> (
    String,
    AdminContext,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let (hub_url, _hub_state) = boot_hub().await;
    let admin = setup_admin(temp, &hub_url).await;
    run_cluster_create(&admin, PASSWORD).await;
    let token = run_vault_invite(&admin, PASSWORD, "pi-1").await;
    let vault = setup_and_accept_vault_with(
        temp,
        "pi-1",
        &hub_url,
        &token,
        VaultSetupOpts {
            listen_addr: Some("/ip4/127.0.0.1/tcp/0".into()),
        },
    )
    .await;
    let vault_cfg = VaultConfig::load(
        Some(&vault.cfg_path),
        vitonomi_vault::config::CliOverrides::default(),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        vitonomi_vault::commands::start::run(vault_cfg)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))
    });
    wait_for_addr(&hub_url, &admin.cli_state_path).await;
    (hub_url, admin, task)
}

async fn wait_for_addr(hub_url: &str, state_path: &std::path::Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let bearer = vitonomi_cli::state::load(state_path)
        .unwrap()
        .session_token
        .as_ref()
        .map(|t| t.0.clone())
        .unwrap();
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("daemon never advertised a libp2p multiaddr");
        }
        if let Ok(r) = client
            .get(format!("{}/v1/vaults", hub_url.trim_end_matches('/')))
            .bearer_auth(&bearer)
            .send()
            .await
        {
            if r.status().is_success() {
                let body: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
                if let Some(vaults) = body.get("vaults").and_then(|v| v.as_array()) {
                    if vaults
                        .iter()
                        .any(|v| v.get("multiaddrs").and_then(|m| m.as_array()).is_some_and(|a| !a.is_empty()))
                    {
                        return;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
