//! Phase 7 Slice 9 e2e: subdomain claim — happy path + privacy
//! invariant (subdomain MUST NOT equal username, enforced
//! client-side only, ZERO HTTP traffic on collision).
//!
//! Drives the real CLI command modules against an in-memory hub
//! booted on an ephemeral port.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vitonomi_cli::commands::subdomain_claim::{run as cli_subdomain_claim, SubdomainClaimArgs};
use vitonomi_cli::config::CliConfig;
use vitonomi_cli::prompts::ScriptedPrompts;

use vitonomi_integration::harness::{boot_hub, run_cluster_create, setup_admin};

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

#[tokio::test]
async fn subdomain_claim_happy_path_succeeds_when_distinct_from_username() {
    let temp = tempfile::tempdir().unwrap();
    let (hub_url, _state) = boot_hub().await;
    let admin = setup_admin(temp.path(), &hub_url).await;
    run_cluster_create(&admin, PASSWORD).await;

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
}

// Suppress unused-import lint — kept for the next test we'll add
// (a counted-HTTP-clients variant that asserts call count == 0).
#[allow(dead_code)]
type _CallCount = Arc<AtomicUsize>;
#[allow(dead_code)]
fn _bump(c: &AtomicUsize) {
    c.fetch_add(1, Ordering::SeqCst);
}
