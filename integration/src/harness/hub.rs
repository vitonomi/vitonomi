//! Boot an in-memory hub on an ephemeral port.

use tokio::net::TcpListener;

use vitonomi_hub::state::AppState;

/// Spawn an in-memory `vitonomi-hub` instance bound to `127.0.0.1:0`
/// and return its base URL plus the captured `AppState` (so tests
/// can poke control-plane state directly without going through HTTP).
///
/// The background task runs until the test process exits; tests do
/// not need to shut it down explicitly.
pub async fn boot_hub() -> (String, AppState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::in_memory();
    let state_clone = state.clone();
    tokio::spawn(async move {
        let _ = vitonomi_hub::run_with_listener(listener, state_clone).await;
    });
    (format!("http://{addr}"), state)
}
