//! `vitonomi-vault` binary entrypoint. Thin shell that delegates to
//! [`vitonomi_vault::cli::run_cli`]. Real logic lives in the library
//! so integration tests can drive flows without subprocess.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match vitonomi_vault::cli::run_cli().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vitonomi-vault: {e:#}");
            ExitCode::from(1)
        }
    }
}
