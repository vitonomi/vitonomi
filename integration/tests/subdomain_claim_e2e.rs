//! Phase 7 Slice 9 e2e: subdomain claim — happy path + privacy
//! invariant (subdomain MUST NOT equal username, enforced
//! client-side only, ZERO HTTP traffic on collision).
//!
//! Drives the real CLI command modules against an in-memory hub
//! booted on an ephemeral port.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use vitonomi_cli::commands::subdomain_claim::{run as cli_subdomain_claim, SubdomainClaimArgs};
use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;
use vitonomi_vault::config::VaultConfig;

use vitonomi_integration::harness::{
    boot_hub, run_cluster_create, run_vault_invite, setup_admin, setup_and_accept_vault_with,
    VaultSetupOpts,
};

const PASSWORD: &str = "subdomain-e2e-pw";

#[tokio::test]
async fn subdomain_claim_rejects_username_collision_with_zero_http_traffic() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    run_cluster_create(&admin, PASSWORD).await;

    // The cluster_create helper uses username = "birkeal".
    // Attempt to claim a subdomain equal to the username — the
    // client-side parse_against_username gate must reject it
    // BEFORE any HTTP request is sent. We assert this by pointing
    // the CLI at an *unreachable* hub URL: if the CLI tried to
    // make any HTTP call, it would error with a connection
    // refused / timeout, not with `subdomain.equals_username`.
    let bad_cfg = {
        let mut c = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
        c.hub.url = "http://127.0.0.1:1".to_string(); // unreachable
        c
    };
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: PASSWORD.into(),
        seed_phrase: String::new(),
    };
    let err = cli_subdomain_claim(
        &bad_cfg,
        SubdomainClaimArgs {
            state_path: &admin.cli_state_path,
            subdomain: "birkeal".into(), // == username
            base_domain: "vito.gg".into(),
        },
        &mut prompts,
    )
    .await
    .expect_err("collision should reject");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("subdomain.equals_username"),
        "expected subdomain.equals_username, got: {msg}"
    );
    // The error must NOT be a network error — if it were, that
    // means the client made an HTTP call (which would violate the
    // zero-HTTP-on-collision invariant).
    assert!(
        !msg.contains("connect")
            && !msg.contains("refused")
            && !msg.contains("timeout"),
        "client made a network call before the privacy check fired: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subdomain_claim_happy_path_succeeds_when_distinct_from_username() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, admin, _vault_task) = boot_full_stack(temp.path()).await;

    let cfg = CliConfig::load(Some(&admin.cli_cfg_path)).unwrap();
    let mut prompts = ScriptedPrompts {
        username: "birkeal".into(),
        password: PASSWORD.into(),
        seed_phrase: String::new(),
    };
    cli_subdomain_claim(
        &cfg,
        SubdomainClaimArgs {
            state_path: &admin.cli_state_path,
            subdomain: "inbox-demo".into(),
            base_domain: "vito.gg".into(),
        },
        &mut prompts,
    )
    .await
    .expect("happy-path claim succeeds against in-memory hub");
    let _ = hub_url;
}

async fn boot_full_stack(
    temp: &std::path::Path,
) -> (
    String,
    vitonomi_integration::harness::AdminContext,
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

// Suppress unused-import lint — kept for the next test we'll add
// (a counted-HTTP-clients variant that asserts call count == 0).
#[allow(dead_code)]
type _CallCount = Arc<AtomicUsize>;
#[allow(dead_code)]
fn _bump(c: &AtomicUsize) {
    c.fetch_add(1, Ordering::SeqCst);
}
